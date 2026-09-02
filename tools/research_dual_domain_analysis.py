# tools\research_dual_domain_analysis.py
"""Predict SHA-256 round trajectories with exact XOR and modular deltas."""

from __future__ import annotations

import argparse
import csv
import inspect
import io
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


MASK32 = 0xFFFFFFFF
WORD_BITS = 32
REGISTERS = ("a", "b", "c", "d", "e", "f", "g", "h")
WORD_OPERATIONS = ("ROTR32", "SHR32", "XOR32", "AND32", "NOT32", "ADD32", "SUB32")
ROUTE_NAMES = (
    "zero_reference_reuse",
    "direct_absolute",
    "xor_differential",
    "modular_differential",
)
GENESIS_NONCE = 2083236893
BIT0_CANDIDATE_NONCE = 2083236892
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
BASELINE_CORE_PER_ROUND = 26
DIRECT_DUAL_PER_ROUND = 42


class AnalysisError(RuntimeError):
    """Raised when an input, prediction, or validation invariant fails."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalysisError(message)


def word(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise AnalysisError(f"{context}: boolean is not a uint32 word")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 16)
        except ValueError as exc:
            raise AnalysisError(f"{context}: invalid hexadecimal word {value!r}") from exc
    else:
        raise AnalysisError(f"{context}: expected an integer or hexadecimal string")
    require(0 <= parsed <= MASK32, f"{context}: value is outside uint32")
    return parsed


def hex32(value: int) -> str:
    return f"{value & MASK32:08x}"


def hamming(value: int) -> int:
    return (value & MASK32).bit_count()


def signed32(value: int) -> int:
    value &= MASK32
    return value if value < 0x80000000 else value - 0x100000000


def rotr32(value: int, amount: int) -> int:
    amount %= WORD_BITS
    return ((value >> amount) | (value << (WORD_BITS - amount))) & MASK32


def big_sigma0(value: int) -> int:
    return rotr32(value, 2) ^ rotr32(value, 13) ^ rotr32(value, 22)


def big_sigma1(value: int) -> int:
    return rotr32(value, 6) ^ rotr32(value, 11) ^ rotr32(value, 25)


def choice_word(x: int, y: int, z: int) -> int:
    return ((x & y) ^ ((~x) & z)) & MASK32


def majority_word(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except FileNotFoundError as exc:
        raise AnalysisError(f"required input file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"invalid JSON in {path}: {exc}") from exc


def find_unique(
    records: Iterable[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
    description: str,
) -> dict[str, Any]:
    matches = [record for record in records if predicate(record)]
    require(len(matches) == 1, f"expected exactly one {description}, found {len(matches)}")
    return matches[0]


def find_trajectory(data: dict[str, Any], nonce: int, role: str) -> dict[str, Any]:
    trajectories = data.get("trajectories")
    require(isinstance(trajectories, list), "trajectories input has no trajectories array")
    return find_unique(
        trajectories,
        lambda record: record.get("nonce") == nonce,
        f"{role} trajectory for nonce {nonce}",
    )


def all_compressions(trajectory: dict[str, Any]) -> list[dict[str, Any]]:
    compressions: list[dict[str, Any]] = []
    for stage_name in ("first_sha", "second_sha"):
        stage = trajectory.get(stage_name)
        if isinstance(stage, dict) and isinstance(stage.get("compressions"), list):
            compressions.extend(stage["compressions"])
    return compressions


def find_compression(
    trajectory: dict[str, Any], sha: int, compression: int, role: str
) -> dict[str, Any]:
    return find_unique(
        all_compressions(trajectory),
        lambda record: record.get("sha") == sha and record.get("compression") == compression,
        f"{role} SHA{sha} compression {compression}",
    )


def find_round(compression: dict[str, Any], round_number: int, role: str) -> dict[str, Any]:
    rounds = compression.get("rounds")
    require(isinstance(rounds, list), f"{role} compression has no rounds array")
    return find_unique(
        rounds,
        lambda record: isinstance(record.get("identity"), dict)
        and record["identity"].get("round") == round_number,
        f"{role} round {round_number}",
    )


def find_comparison(data: dict[str, Any], nonce: int) -> dict[str, Any]:
    comparisons = data.get("comparisons")
    require(isinstance(comparisons, list), "diffusion input has no comparisons array")
    return find_unique(
        comparisons,
        lambda record: record.get("nonce") == nonce,
        f"diffusion comparison for candidate nonce {nonce}",
    )


def find_diffusion_round(
    comparison: dict[str, Any], sha: int, compression: int, round_number: int
) -> dict[str, Any]:
    rounds = comparison.get("rounds")
    require(isinstance(rounds, list), "diffusion comparison has no rounds array")
    return find_unique(
        rounds,
        lambda record: record.get("sha") == sha
        and record.get("compression") == compression
        and record.get("round") == round_number,
        f"diffusion SHA{sha} compression {compression} round {round_number}",
    )


def state_words(round_record: Mapping[str, Any], phase: str, context: str) -> dict[str, int]:
    state = round_record.get(phase)
    require(isinstance(state, dict), f"{context}: missing {phase} state")
    return {
        register: word(state.get(register), f"{context}.{phase}.{register}")
        for register in REGISTERS
    }


def schedule_word(compression: Mapping[str, Any], round_number: int, context: str) -> int:
    schedule = compression.get("message_schedule")
    require(isinstance(schedule, dict), f"{context}: missing message_schedule")
    words = schedule.get("words")
    require(isinstance(words, list), f"{context}: missing message schedule words")
    record = find_unique(
        words,
        lambda item: item.get("round") == round_number,
        f"{context} message schedule round {round_number}",
    )
    key = "w" if "w" in record else "result_w"
    require(key in record, f"{context}: schedule round {round_number} has no word")
    return word(record[key], f"{context}.message_schedule.round{round_number}.{key}")


@dataclass(frozen=True)
class DualDomainWord:
    """A predicted uint32 word represented in absolute, XOR, and modular domains."""

    reference_abs: int
    predicted_candidate_abs: int
    xor_delta: int
    modular_delta: int

    def __post_init__(self) -> None:
        for name in (
            "reference_abs",
            "predicted_candidate_abs",
            "xor_delta",
            "modular_delta",
        ):
            value = getattr(self, name)
            require(0 <= value <= MASK32, f"DualDomainWord.{name} is outside uint32")
        require(
            self.predicted_candidate_abs == (self.reference_abs ^ self.xor_delta),
            "DualDomainWord XOR reconstruction failed",
        )
        require(
            self.predicted_candidate_abs
            == ((self.reference_abs + self.modular_delta) & MASK32),
            "DualDomainWord modular reconstruction failed",
        )

    @classmethod
    def from_absolute(cls, reference_abs: int, predicted_candidate_abs: int) -> "DualDomainWord":
        reference_abs &= MASK32
        predicted_candidate_abs &= MASK32
        return cls(
            reference_abs=reference_abs,
            predicted_candidate_abs=predicted_candidate_abs,
            xor_delta=reference_abs ^ predicted_candidate_abs,
            modular_delta=(predicted_candidate_abs - reference_abs) & MASK32,
        )

    @classmethod
    def from_xor(cls, reference_abs: int, xor_delta: int) -> "DualDomainWord":
        reference_abs &= MASK32
        xor_delta &= MASK32
        predicted_candidate_abs = reference_abs ^ xor_delta
        return cls(
            reference_abs=reference_abs,
            predicted_candidate_abs=predicted_candidate_abs,
            xor_delta=xor_delta,
            modular_delta=(predicted_candidate_abs - reference_abs) & MASK32,
        )

    @classmethod
    def from_modular(cls, reference_abs: int, modular_delta: int) -> "DualDomainWord":
        reference_abs &= MASK32
        modular_delta &= MASK32
        predicted_candidate_abs = (reference_abs + modular_delta) & MASK32
        return cls(
            reference_abs=reference_abs,
            predicted_candidate_abs=predicted_candidate_abs,
            xor_delta=reference_abs ^ predicted_candidate_abs,
            modular_delta=modular_delta,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "difference_direction": "candidate_minus_reference",
            "reference_abs_hex": hex32(self.reference_abs),
            "predicted_candidate_abs_hex": hex32(self.predicted_candidate_abs),
            "xor_delta_hex": hex32(self.xor_delta),
            "xor_hamming": hamming(self.xor_delta),
            "mod_delta_hex": hex32(self.modular_delta),
            "modular_delta_hex": hex32(self.modular_delta),
            "mod_delta_signed32": signed32(self.modular_delta),
            "modular_delta_signed32": signed32(self.modular_delta),
            "domain_consistency_validated": True,
        }


def empty_breakdown(**counts: int) -> dict[str, int]:
    breakdown = {operation: 0 for operation in WORD_OPERATIONS}
    for operation, count in counts.items():
        require(operation in breakdown, f"unknown word operation {operation}")
        require(isinstance(count, int) and count >= 0, f"invalid count for {operation}")
        breakdown[operation] = count
    return breakdown


def breakdown_total(breakdown: Mapping[str, int]) -> int:
    require(set(breakdown) == set(WORD_OPERATIONS), "word operation breakdown has wrong keys")
    return sum(breakdown.values())


def route(
    name: str,
    valid: bool,
    breakdown: dict[str, int],
    reason: str,
) -> dict[str, Any]:
    require(name in ROUTE_NAMES, f"unexpected route name {name}")
    return {
        "name": name,
        "valid": valid,
        "word_op_cost": breakdown_total(breakdown) if valid else None,
        "breakdown": breakdown,
        "reason": reason,
    }


@dataclass(frozen=True)
class OperationPrediction:
    name: str
    family: str
    value: DualDomainWord
    recipe: str
    routes: tuple[dict[str, Any], ...]
    chosen_route: str
    domain_conversions: tuple[str, ...]
    zero_delta_shortcut: bool
    reference_reuse: bool
    algebraic_validation: dict[str, Any]

    @property
    def chosen(self) -> dict[str, Any]:
        matches = [candidate for candidate in self.routes if candidate["name"] == self.chosen_route]
        require(len(matches) == 1, f"{self.name}: chosen route is absent or duplicated")
        require(matches[0]["valid"], f"{self.name}: chosen route is invalid")
        admissible_costs = [candidate["word_op_cost"] for candidate in self.routes if candidate["valid"]]
        require(
            matches[0]["word_op_cost"] == min(admissible_costs),
            f"{self.name}: chosen route is not minimum-cost",
        )
        return matches[0]

    @property
    def cost(self) -> int:
        return int(self.chosen["word_op_cost"])

    def as_dict(self) -> dict[str, Any]:
        output = self.value.as_dict()
        output.update(
            {
                "operation": self.name,
                "operation_family": self.family,
                "candidate_prediction_recipe": self.recipe,
                "routes_considered": list(self.routes),
                "chosen_route": self.chosen_route,
                "chosen_word_op_cost": self.cost,
                "chosen_breakdown": self.chosen["breakdown"],
                "domain_conversions": list(self.domain_conversions),
                "zero_delta_shortcut": self.zero_delta_shortcut,
                "reference_reuse": self.reference_reuse,
                "algebraic_validation": self.algebraic_validation,
            }
        )
        return output


class RoundLedger:
    """Deterministic primary arithmetic and auxiliary-event ledger."""

    def __init__(self) -> None:
        self.counts = Counter({operation: 0 for operation in WORD_OPERATIONS})
        self.domain_conversions: Counter[str] = Counter()
        self.zero_delta_shortcuts = 0
        self.reference_word_reads = 0
        self.external_w_reads = 0
        self.external_w_domain_materialization_word_ops = 0

    def add_breakdown(self, breakdown: Mapping[str, int]) -> None:
        breakdown_total(breakdown)
        self.counts.update(breakdown)

    def add_operation(self, prediction: OperationPrediction) -> None:
        self.add_breakdown(prediction.chosen["breakdown"])
        self.domain_conversions.update(prediction.domain_conversions)
        if prediction.zero_delta_shortcut:
            self.zero_delta_shortcuts += 1

    def add_external_w(self, external_w: dict[str, Any]) -> None:
        self.external_w_reads += 1
        materialization = external_w["domain_materialization"]
        self.add_breakdown(materialization["breakdown"])
        self.external_w_domain_materialization_word_ops += materialization["word_op_cost"]
        self.domain_conversions.update(materialization["domain_conversions"])

    @property
    def total(self) -> int:
        return sum(self.counts[operation] for operation in WORD_OPERATIONS)

    def as_dict(self) -> dict[str, Any]:
        return {
            "word_operation_counts": {
                operation: self.counts[operation] for operation in WORD_OPERATIONS
            },
            "hybrid_dual_tracking_word_ops": self.total,
            "operation_prediction_word_ops": self.total
            - self.external_w_domain_materialization_word_ops,
            "external_w_domain_materialization_word_ops": (
                self.external_w_domain_materialization_word_ops
            ),
            "direct_dual_tracking_word_ops": DIRECT_DUAL_PER_ROUND,
            "baseline_sha_round_core_word_ops": BASELINE_CORE_PER_ROUND,
            "hybrid_vs_baseline_core_ratio": self.total / BASELINE_CORE_PER_ROUND,
            "hybrid_vs_direct_dual_tracking_ratio": self.total / DIRECT_DUAL_PER_ROUND,
            "zero_delta_shortcut_count": self.zero_delta_shortcuts,
            "domain_conversion_counts": dict(sorted(self.domain_conversions.items())),
            "domain_conversion_count": sum(self.domain_conversions.values()),
            "reference_word_reads": self.reference_word_reads,
            "external_w_reads": self.external_w_reads,
        }


def recorded_reference_components(
    reference_round: Mapping[str, Any],
    sha: int,
    compression: int,
    round_number: int,
) -> dict[str, Any]:
    """Read and fully validate one reference round before prediction."""
    context = f"SHA{sha} compression {compression} round {round_number} reference"
    identity = {"compression": compression, "round": round_number, "sha": sha}
    require(reference_round.get("identity") == identity, f"{context}: bad identity")
    before = state_words(reference_round, "before", context)
    after = state_words(reference_round, "after", context)
    w = word(reference_round.get("message", {}).get("w"), f"{context}.message.w")
    derived_k = word(reference_round.get("derived_k"), f"{context}.derived_k")
    sigma0_record = reference_round.get("large_sigma0")
    sigma1_record = reference_round.get("large_sigma1")
    functions = reference_round.get("functions")
    require(isinstance(sigma0_record, dict), f"{context}: missing large_sigma0")
    require(isinstance(sigma1_record, dict), f"{context}: missing large_sigma1")
    require(isinstance(functions, dict), f"{context}: missing functions")
    expected_operations = {
        "sum0": big_sigma0(before["a"]),
        "sum1": big_sigma1(before["e"]),
        "choice": choice_word(before["e"], before["f"], before["g"]),
        "majority": majority_word(before["a"], before["b"], before["c"]),
    }
    observed_operations = {
        "sum0": word(sigma0_record.get("sum0"), f"{context}.large_sigma0.sum0"),
        "sum1": word(sigma1_record.get("sum1"), f"{context}.large_sigma1.sum1"),
        "choice": word(functions.get("choice"), f"{context}.functions.choice"),
        "majority": word(functions.get("majority"), f"{context}.functions.majority"),
    }
    require(observed_operations == expected_operations, f"{context}: primitive record mismatch")
    temp1_record = reference_round.get("temp1")
    temp2_record = reference_round.get("temp2")
    construction = reference_round.get("state_construction")
    require(isinstance(temp1_record, dict), f"{context}: missing temp1")
    require(isinstance(temp2_record, dict), f"{context}: missing temp2")
    require(isinstance(construction, dict), f"{context}: missing state_construction")
    new_a_record = construction.get("new_a")
    new_e_record = construction.get("new_e")
    require(isinstance(new_a_record, dict), f"{context}: missing new_a")
    require(isinstance(new_e_record, dict), f"{context}: missing new_e")
    expected_operations["temp1"] = (
        before["h"]
        + expected_operations["sum1"]
        + expected_operations["choice"]
        + derived_k
        + w
    ) & MASK32
    expected_operations["temp2"] = (
        expected_operations["sum0"] + expected_operations["majority"]
    ) & MASK32
    expected_operations["new_a"] = (
        expected_operations["temp1"] + expected_operations["temp2"]
    ) & MASK32
    expected_operations["new_e"] = (before["d"] + expected_operations["temp1"]) & MASK32
    observed_operations.update(
        {
            "temp1": word(temp1_record.get("result"), f"{context}.temp1.result"),
            "temp2": word(temp2_record.get("result"), f"{context}.temp2.result"),
            "new_a": word(new_a_record.get("result"), f"{context}.new_a.result"),
            "new_e": word(new_e_record.get("result"), f"{context}.new_e.result"),
        }
    )
    require(observed_operations == expected_operations, f"{context}: addition record mismatch")
    expected_after = {
        "a": expected_operations["new_a"],
        "b": before["a"],
        "c": before["b"],
        "d": before["c"],
        "e": expected_operations["new_e"],
        "f": before["e"],
        "g": before["f"],
        "h": before["g"],
    }
    require(after == expected_after, f"{context}: output state does not match round construction")
    return {
        "identity": identity,
        "before": before,
        "after": after,
        "w": w,
        "derived_k": derived_k,
        "operations": observed_operations,
    }


def predict_sigma(
    name: str,
    input_word: DualDomainWord,
    reference_output: int,
    function: Callable[[int], int],
) -> OperationPrediction:
    input_is_zero = input_word.xor_delta == 0
    differential_delta = function(input_word.xor_delta)
    direct_candidate = function(input_word.predicted_candidate_abs)
    require(
        differential_delta == (reference_output ^ direct_candidate),
        f"{name}: Sigma XOR-linearity identity failed",
    )
    direct_value = DualDomainWord.from_absolute(reference_output, direct_candidate)
    differential_value = DualDomainWord.from_xor(reference_output, differential_delta)
    require(direct_value == differential_value, f"{name}: direct and differential routes disagree")
    routes = (
        route(
            "zero_reference_reuse",
            input_is_zero,
            empty_breakdown(),
            "input XOR delta is zero" if input_is_zero else "input XOR delta is nonzero",
        ),
        route(
            "direct_absolute",
            True,
            empty_breakdown(ROTR32=3, XOR32=3, SUB32=1),
            "3 ROTR + 2 XOR primitive, then ABS->XOR and ABS->MOD",
        ),
        route(
            "xor_differential",
            True,
            empty_breakdown(ROTR32=3, XOR32=3, SUB32=1),
            "Sigma(delta XOR), then XOR->ABS and ABS->MOD",
        ),
    )
    if input_is_zero:
        chosen = "zero_reference_reuse"
        value = DualDomainWord.from_absolute(reference_output, reference_output)
        conversions: tuple[str, ...] = ()
        recipe = "reuse the reference Sigma output because the predicted input XOR delta is zero"
    else:
        chosen = "xor_differential"
        value = differential_value
        conversions = ("XOR_to_ABS", "ABS_to_MOD")
        recipe = "apply Sigma to the predicted XOR delta, reconstruct ABS, then derive MOD"
    return OperationPrediction(
        name=name,
        family="Sigma",
        value=value,
        recipe=recipe,
        routes=routes,
        chosen_route=chosen,
        domain_conversions=conversions,
        zero_delta_shortcut=input_is_zero,
        reference_reuse=input_is_zero,
        algebraic_validation={
            "xor_linearity_identity_validated": True,
            "direct_and_differential_predictions_match": True,
            "tie_policy": "prefer_xor_differential_for_nonzero_Sigma_delta",
        },
    )


def choice_differential(inputs: Sequence[DualDomainWord]) -> int:
    x, y, z = inputs
    dx, dy, dz = x.xor_delta, y.xor_delta, z.xor_delta
    u = dy ^ dz
    v = y.reference_abs ^ z.reference_abs
    return (
        dz
        ^ (x.reference_abs & u)
        ^ (dx & v)
        ^ (dx & u)
    ) & MASK32


def majority_differential(inputs: Sequence[DualDomainWord]) -> int:
    x, y, z = inputs
    dx, dy, dz = x.xor_delta, y.xor_delta, z.xor_delta
    u = dx ^ dy
    v = x.reference_abs ^ y.reference_abs
    return (
        (x.reference_abs & dy)
        ^ (y.reference_abs & dx)
        ^ (dx & dy)
        ^ (z.reference_abs & u)
        ^ (dz & v)
        ^ (dz & u)
    ) & MASK32


def predict_boolean(
    name: str,
    inputs: Sequence[DualDomainWord],
    reference_output: int,
    function: Callable[[int, int, int], int],
    differential_function: Callable[[Sequence[DualDomainWord]], int],
) -> OperationPrediction:
    require(len(inputs) == 3, f"{name}: expected three inputs")
    all_zero = all(input_word.xor_delta == 0 for input_word in inputs)
    direct_candidate = function(*(item.predicted_candidate_abs for item in inputs))
    differential_delta = differential_function(inputs)
    require(
        differential_delta == (reference_output ^ direct_candidate),
        f"{name}: exact XOR differential identity failed",
    )
    direct_value = DualDomainWord.from_absolute(reference_output, direct_candidate)
    differential_value = DualDomainWord.from_xor(reference_output, differential_delta)
    require(direct_value == differential_value, f"{name}: direct and differential routes disagree")
    if name == "choice":
        direct_breakdown = empty_breakdown(XOR32=2, AND32=2, NOT32=1, SUB32=1)
        differential_breakdown = empty_breakdown(XOR32=6, AND32=3, SUB32=1)
        canonical_formula = "dCh exact formula: 5 XOR + 3 AND"
    else:
        direct_breakdown = empty_breakdown(XOR32=3, AND32=3, SUB32=1)
        differential_breakdown = empty_breakdown(XOR32=8, AND32=6, SUB32=1)
        canonical_formula = "dMaj exact formula: 7 XOR + 6 AND"
    routes = (
        route(
            "zero_reference_reuse",
            all_zero,
            empty_breakdown(),
            "all input XOR deltas are zero" if all_zero else "at least one input delta is nonzero",
        ),
        route(
            "direct_absolute",
            True,
            direct_breakdown,
            "compute predicted candidate primitive, then ABS->XOR and ABS->MOD",
        ),
        route(
            "xor_differential",
            True,
            differential_breakdown,
            f"{canonical_formula}, then XOR->ABS and ABS->MOD",
        ),
    )
    if all_zero:
        chosen = "zero_reference_reuse"
        value = DualDomainWord.from_absolute(reference_output, reference_output)
        conversions: tuple[str, ...] = ()
        recipe = "reuse the reference Boolean output because every predicted input delta is zero"
    else:
        chosen = "direct_absolute"
        value = direct_value
        conversions = ("ABS_to_XOR", "ABS_to_MOD")
        recipe = "compute the Boolean primitive from predicted candidate inputs, then derive both deltas"
    return OperationPrediction(
        name=name,
        family="Boolean",
        value=value,
        recipe=recipe,
        routes=routes,
        chosen_route=chosen,
        domain_conversions=conversions,
        zero_delta_shortcut=all_zero,
        reference_reuse=all_zero,
        algebraic_validation={
            "exact_xor_differential_identity_validated": True,
            "direct_and_differential_predictions_match": True,
            "differential_formula": canonical_formula,
        },
    )


def predict_addition(
    name: str,
    operands: Sequence[DualDomainWord],
    reference_result: int,
) -> OperationPrediction:
    require(len(operands) >= 2, f"{name}: expected at least two operands")
    require(
        sum(item.reference_abs for item in operands) & MASK32 == reference_result,
        f"{name}: reference result does not equal modular operand sum",
    )
    direct_candidate = sum(item.predicted_candidate_abs for item in operands) & MASK32
    nonzero_modular_deltas = [item.modular_delta for item in operands if item.modular_delta != 0]
    k = len(nonzero_modular_deltas)
    output_modular_delta = sum(nonzero_modular_deltas) & MASK32
    modular_value = DualDomainWord.from_modular(reference_result, output_modular_delta)
    direct_value = DualDomainWord.from_absolute(reference_result, direct_candidate)
    require(direct_value == modular_value, f"{name}: modular addition identity failed")
    direct_breakdown = empty_breakdown(ADD32=len(operands) - 1, XOR32=1, SUB32=1)
    modular_breakdown = (
        empty_breakdown()
        if k == 0
        else empty_breakdown(ADD32=k, XOR32=1)
    )
    routes = (
        route(
            "zero_reference_reuse",
            k == 0,
            empty_breakdown(),
            "all operand modular deltas are zero" if k == 0 else "nonzero modular operand delta exists",
        ),
        route(
            "direct_absolute",
            True,
            direct_breakdown,
            "sum predicted candidate operands, then ABS->XOR and ABS->MOD",
        ),
        route(
            "modular_differential",
            k >= 1,
            modular_breakdown,
            (
                f"sum {k} nonzero modular deltas, then MOD->ABS and ABS->XOR"
                if k >= 1
                else "zero delta is handled by zero_reference_reuse"
            ),
        ),
    )
    if k == 0:
        chosen = "zero_reference_reuse"
        value = DualDomainWord.from_absolute(reference_result, reference_result)
        conversions: tuple[str, ...] = ()
        recipe = "reuse the reference addition result because all modular operand deltas are zero"
    elif breakdown_total(modular_breakdown) < breakdown_total(direct_breakdown):
        chosen = "modular_differential"
        value = modular_value
        conversions = ("MOD_to_ABS", "ABS_to_XOR")
        recipe = "sum nonzero modular deltas, reconstruct candidate ABS, then derive XOR"
    else:
        chosen = "direct_absolute"
        value = direct_value
        conversions = ("ABS_to_XOR", "ABS_to_MOD")
        recipe = "compute the absolute modular sum, then derive XOR and modular deltas"
    return OperationPrediction(
        name=name,
        family="Addition",
        value=value,
        recipe=recipe,
        routes=routes,
        chosen_route=chosen,
        domain_conversions=conversions,
        zero_delta_shortcut=k == 0,
        reference_reuse=k == 0,
        algebraic_validation={
            "modular_addition_identity_validated": True,
            "direct_and_modular_predictions_match": True,
            "nonzero_modular_operand_delta_count": k,
            "addition_tie_policy": "prefer_direct_absolute",
        },
    )


@dataclass(frozen=True)
class RoundPrediction:
    identity: dict[str, int]
    input_state: dict[str, DualDomainWord]
    external_w: DualDomainWord
    external_w_report: dict[str, Any]
    operations: dict[str, OperationPrediction]
    output_state: dict[str, DualDomainWord]
    reference_components: dict[str, Any]
    cost_summary: dict[str, Any]

    def as_dict(
        self,
        oracle_validation: dict[str, Any],
        diffusion_validation: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "input_state": {
                register: value.as_dict() for register, value in self.input_state.items()
            },
            "external_w": self.external_w_report,
            "operations": {
                name: prediction.as_dict() for name, prediction in self.operations.items()
            },
            "output_state": {
                register: value.as_dict() for register, value in self.output_state.items()
            },
            "cost_summary": self.cost_summary,
            "oracle_validation": oracle_validation,
            "diffusion_cross_check": diffusion_validation,
        }


def external_w_dual_word(reference_w: int, candidate_w: int) -> tuple[DualDomainWord, dict[str, Any]]:
    """Materialize the two deltas for the sole authorized external candidate input."""
    value = DualDomainWord.from_absolute(reference_w, candidate_w)
    if value.xor_delta == 0:
        breakdown = empty_breakdown()
        conversions: tuple[str, ...] = ()
        recipe = "reuse zero XOR and modular deltas after exact external-input equality"
        reference_reuse = True
    else:
        breakdown = empty_breakdown(XOR32=1, SUB32=1)
        conversions = ("ABS_to_XOR", "ABS_to_MOD")
        recipe = "derive XOR and modular deltas from external candidate W"
        reference_reuse = False
    report = value.as_dict()
    report.update(
        {
            "input_role": "authorized_external_candidate_w",
            "candidate_prediction_recipe": recipe,
            "reference_reuse": reference_reuse,
            "domain_materialization": {
                "breakdown": breakdown,
                "word_op_cost": breakdown_total(breakdown),
                "domain_conversions": list(conversions),
                "zero_delta_input_reuse": reference_reuse,
            },
        }
    )
    return value, report


def predict_round(
    reference_round: Mapping[str, Any],
    predicted_input_state: Mapping[str, DualDomainWord],
    external_w: int,
    *,
    sha: int,
    compression: int,
    round_number: int,
) -> RoundPrediction:
    """Phase A: predict a complete round without any candidate-round oracle input."""
    reference = recorded_reference_components(
        reference_round, sha, compression, round_number
    )
    require(set(predicted_input_state) == set(REGISTERS), "predicted input state has wrong registers")
    for register in REGISTERS:
        require(
            predicted_input_state[register].reference_abs == reference["before"][register],
            f"round {round_number}: predicted {register} reference input is discontinuous",
        )
    w_value, w_report = external_w_dual_word(reference["w"], external_w)
    operations: dict[str, OperationPrediction] = {}
    operations["sum0"] = predict_sigma(
        "sum0",
        predicted_input_state["a"],
        reference["operations"]["sum0"],
        big_sigma0,
    )
    operations["sum1"] = predict_sigma(
        "sum1",
        predicted_input_state["e"],
        reference["operations"]["sum1"],
        big_sigma1,
    )
    operations["choice"] = predict_boolean(
        "choice",
        tuple(predicted_input_state[name] for name in ("e", "f", "g")),
        reference["operations"]["choice"],
        choice_word,
        choice_differential,
    )
    operations["majority"] = predict_boolean(
        "majority",
        tuple(predicted_input_state[name] for name in ("a", "b", "c")),
        reference["operations"]["majority"],
        majority_word,
        majority_differential,
    )
    k_value = DualDomainWord.from_absolute(reference["derived_k"], reference["derived_k"])
    operations["temp1"] = predict_addition(
        "temp1",
        (
            predicted_input_state["h"],
            operations["sum1"].value,
            operations["choice"].value,
            k_value,
            w_value,
        ),
        reference["operations"]["temp1"],
    )
    operations["temp2"] = predict_addition(
        "temp2",
        (operations["sum0"].value, operations["majority"].value),
        reference["operations"]["temp2"],
    )
    operations["new_a"] = predict_addition(
        "new_a",
        (operations["temp1"].value, operations["temp2"].value),
        reference["operations"]["new_a"],
    )
    operations["new_e"] = predict_addition(
        "new_e",
        (predicted_input_state["d"], operations["temp1"].value),
        reference["operations"]["new_e"],
    )
    output_state = {
        "a": operations["new_a"].value,
        "b": predicted_input_state["a"],
        "c": predicted_input_state["b"],
        "d": predicted_input_state["c"],
        "e": operations["new_e"].value,
        "f": predicted_input_state["e"],
        "g": predicted_input_state["f"],
        "h": predicted_input_state["g"],
    }
    for register in REGISTERS:
        require(
            output_state[register].reference_abs == reference["after"][register],
            f"round {round_number}: predicted {register} reference output is inconsistent",
        )
    ledger = RoundLedger()
    ledger.reference_word_reads = 18
    ledger.add_external_w(w_report)
    for prediction in operations.values():
        ledger.add_operation(prediction)
    cost_summary = ledger.as_dict()
    require(
        DIRECT_DUAL_PER_ROUND
        == sum((7, 7, 6, 7, 6, 3, 3, 3)),
        "direct dual-tracking baseline constant is inconsistent",
    )
    require(
        BASELINE_CORE_PER_ROUND
        == sum((5, 5, 4, 5, 4, 1, 1, 1)),
        "baseline SHA round-core constant is inconsistent",
    )
    return RoundPrediction(
        identity=reference["identity"],
        input_state=dict(predicted_input_state),
        external_w=w_value,
        external_w_report=w_report,
        operations=operations,
        output_state=output_state,
        reference_components=reference,
        cost_summary=cost_summary,
    )


def recorded_candidate_operation_values(
    candidate_round: Mapping[str, Any], context: str
) -> dict[str, int]:
    """Oracle-only extraction of recorded candidate intermediates."""
    sigma0 = candidate_round.get("large_sigma0")
    sigma1 = candidate_round.get("large_sigma1")
    functions = candidate_round.get("functions")
    construction = candidate_round.get("state_construction")
    require(isinstance(sigma0, dict), f"{context}: missing large_sigma0")
    require(isinstance(sigma1, dict), f"{context}: missing large_sigma1")
    require(isinstance(functions, dict), f"{context}: missing functions")
    require(isinstance(construction, dict), f"{context}: missing state_construction")
    temp1 = candidate_round.get("temp1")
    temp2 = candidate_round.get("temp2")
    new_a = construction.get("new_a")
    new_e = construction.get("new_e")
    require(isinstance(temp1, dict), f"{context}: missing temp1")
    require(isinstance(temp2, dict), f"{context}: missing temp2")
    require(isinstance(new_a, dict), f"{context}: missing new_a")
    require(isinstance(new_e, dict), f"{context}: missing new_e")
    return {
        "sum0": word(sigma0.get("sum0"), f"{context}.large_sigma0.sum0"),
        "sum1": word(sigma1.get("sum1"), f"{context}.large_sigma1.sum1"),
        "choice": word(functions.get("choice"), f"{context}.functions.choice"),
        "majority": word(functions.get("majority"), f"{context}.functions.majority"),
        "temp1": word(temp1.get("result"), f"{context}.temp1.result"),
        "temp2": word(temp2.get("result"), f"{context}.temp2.result"),
        "new_a": word(new_a.get("result"), f"{context}.new_a.result"),
        "new_e": word(new_e.get("result"), f"{context}.new_e.result"),
    }


class CandidateOracle:
    """Own all access to candidate rounds and enforce post-prediction validation."""

    def __init__(self, compression: dict[str, Any]) -> None:
        self._compression = compression
        self._external_w_rounds: set[int] = set()
        self._validated_rounds: set[int] = set()
        self._bootstrapped_rounds: set[int] = set()

    def _round(self, round_number: int) -> dict[str, Any]:
        return find_round(self._compression, round_number, "candidate oracle")

    def external_w(self, round_number: int) -> int:
        """Expose only the explicitly authorized candidate W input before prediction."""
        candidate_round = self._round(round_number)
        self._external_w_rounds.add(round_number)
        return word(
            candidate_round.get("message", {}).get("w"),
            f"candidate oracle round {round_number}.message.w",
        )

    def bootstrap_before(self, round_number: int) -> dict[str, int]:
        """Explicit, opt-in bootstrap for a non-default arbitrary start."""
        candidate_round = self._round(round_number)
        self._bootstrapped_rounds.add(round_number)
        return state_words(candidate_round, "before", f"candidate oracle round {round_number}")

    def validate_round(
        self,
        prediction: RoundPrediction,
        candidate_external_w: int,
    ) -> dict[str, Any]:
        """Phase B: open the candidate round only after its complete prediction exists."""
        round_number = prediction.identity["round"]
        require(round_number not in self._validated_rounds, f"round {round_number}: oracle reused")
        require(
            round_number in self._external_w_rounds,
            f"round {round_number}: candidate W was not obtained through the authorized channel",
        )
        candidate_round = self._round(round_number)
        context = f"candidate oracle round {round_number}"
        require(candidate_round.get("identity") == prediction.identity, f"{context}: bad identity")
        candidate_before = state_words(candidate_round, "before", context)
        candidate_after = state_words(candidate_round, "after", context)
        predicted_before = {
            register: prediction.input_state[register].predicted_candidate_abs
            for register in REGISTERS
        }
        predicted_after = {
            register: prediction.output_state[register].predicted_candidate_abs
            for register in REGISTERS
        }
        require(candidate_before == predicted_before, f"{context}: BEFORE state prediction mismatch")
        require(candidate_after == predicted_after, f"{context}: AFTER state prediction mismatch")
        recorded_w = word(candidate_round.get("message", {}).get("w"), f"{context}.message.w")
        require(recorded_w == candidate_external_w, f"{context}: W input changed before oracle validation")
        require(
            schedule_word(self._compression, round_number, context) == recorded_w,
            f"{context}: W differs from candidate message schedule",
        )
        candidate_k = word(candidate_round.get("derived_k"), f"{context}.derived_k")
        require(
            candidate_k == prediction.reference_components["derived_k"],
            f"{context}: derived_k differs from reference",
        )
        recorded_operations = recorded_candidate_operation_values(candidate_round, context)
        predicted_operations = {
            name: operation.value.predicted_candidate_abs
            for name, operation in prediction.operations.items()
        }
        require(
            recorded_operations == predicted_operations,
            f"{context}: intermediate operation prediction mismatch",
        )
        self._validated_rounds.add(round_number)
        compared_paths = (
            [f"before.{register}" for register in REGISTERS]
            + [f"operations.{name}" for name in prediction.operations]
            + [f"after.{register}" for register in REGISTERS]
            + ["message.w"]
        )
        return {
            "oracle_validation_passed": True,
            "validation_phase": "after_complete_round_prediction",
            "validated_paths": compared_paths,
            "validated_value_count": len(compared_paths),
            "derived_k_equality_validated": True,
            "candidate_message_schedule_w_validated": True,
            "candidate_round_not_supplied_to_predict_round": True,
        }


def state_hamming(state: Mapping[str, DualDomainWord]) -> tuple[int, dict[str, int]]:
    registers = {register: hamming(state[register].xor_delta) for register in REGISTERS}
    return sum(registers.values()), registers


def validate_diffusion(
    prediction: RoundPrediction,
    diffusion_round: Mapping[str, Any],
) -> dict[str, Any]:
    round_number = prediction.identity["round"]
    input_total, input_registers = state_hamming(prediction.input_state)
    output_total, output_registers = state_hamming(prediction.output_state)
    a_delta = prediction.input_state["a"].xor_delta
    e_delta = prediction.input_state["e"].xor_delta
    recomputed = {
        "w_hamming": hamming(prediction.external_w.xor_delta),
        "rotr2_a_hamming": hamming(rotr32(a_delta, 2)),
        "rotr13_a_hamming": hamming(rotr32(a_delta, 13)),
        "rotr22_a_hamming": hamming(rotr32(a_delta, 22)),
        "sum0_hamming": prediction.operations["sum0"].value.as_dict()["xor_hamming"],
        "rotr6_e_hamming": hamming(rotr32(e_delta, 6)),
        "rotr11_e_hamming": hamming(rotr32(e_delta, 11)),
        "rotr25_e_hamming": hamming(rotr32(e_delta, 25)),
        "sum1_hamming": prediction.operations["sum1"].value.as_dict()["xor_hamming"],
        "choice_hamming": prediction.operations["choice"].value.as_dict()["xor_hamming"],
        "majority_hamming": prediction.operations["majority"].value.as_dict()["xor_hamming"],
        "temp1_hamming": prediction.operations["temp1"].value.as_dict()["xor_hamming"],
        "temp2_hamming": prediction.operations["temp2"].value.as_dict()["xor_hamming"],
    }
    for metric, value in recomputed.items():
        require(
            diffusion_round.get(metric) == value,
            f"round {round_number}: diffusion {metric} mismatch: "
            f"recorded={diffusion_round.get(metric)!r}, predicted={value}",
        )
    for phase, total, registers in (
        ("before", input_total, input_registers),
        ("after", output_total, output_registers),
    ):
        record = diffusion_round.get(phase)
        require(isinstance(record, dict), f"round {round_number}: diffusion missing {phase}")
        require(record.get("total_hamming") == total, f"round {round_number}: {phase} total mismatch")
        for register in REGISTERS:
            require(
                record.get(register) == registers[register],
                f"round {round_number}: diffusion {phase}.{register} mismatch",
            )
    return {
        "passed": True,
        "metrics_validated": sorted(recomputed),
        "input_state_hamming": input_total,
        "output_state_hamming": output_total,
    }


def validate_bit0_metadata(
    trajectory: Mapping[str, Any], comparison: Mapping[str, Any]
) -> None:
    def validate_labels(labels: Any, context: str) -> None:
        require(isinstance(labels, list), f"{context}: labels missing")
        bit0 = [
            label
            for label in labels
            if isinstance(label, dict)
            and label.get("kind") == "single_bit_flip"
            and label.get("bit") == 0
        ]
        neighbor = [
            label
            for label in labels
            if isinstance(label, dict)
            and label.get("kind") == "neighbor"
            and label.get("delta") == -1
        ]
        require(len(bit0) == 1, f"{context}: expected one bit-0 label")
        require(len(neighbor) == 1, f"{context}: expected one neighbor -1 label")
        require(bit0[0].get("w3_hamming") == 1, f"{context}: bit-0 W3 hamming mismatch")
        require(bit0[0].get("w3_changed_bit") == 24, f"{context}: W3 changed bit mismatch")

    validate_labels(trajectory.get("labels"), "candidate trajectory")
    validate_labels(comparison.get("labels"), "diffusion comparison")


def initial_prediction_state(
    reference_round: Mapping[str, Any],
    oracle: CandidateOracle,
    *,
    sha: int,
    compression: int,
    round_start: int,
    strict_genesis_bit0_start: bool,
    allow_recorded_candidate_bootstrap: bool,
) -> tuple[dict[str, DualDomainWord], bool]:
    reference_before = state_words(reference_round, "before", "initial reference round")
    if strict_genesis_bit0_start:
        require(
            not allow_recorded_candidate_bootstrap,
            "--allow-recorded-candidate-bootstrap is forbidden for the strict Genesis round-4 start",
        )
        return {
            register: DualDomainWord.from_absolute(value, value)
            for register, value in reference_before.items()
        }, False
    require(
        allow_recorded_candidate_bootstrap,
        f"SHA{sha} compression {compression} round-start {round_start} requires "
        "--allow-recorded-candidate-bootstrap",
    )
    candidate_before = oracle.bootstrap_before(round_start)
    return {
        register: DualDomainWord.from_absolute(reference_before[register], candidate_before[register])
        for register in REGISTERS
    }, True


def default_sanity_checks(
    prediction: RoundPrediction,
    reference_nonce: int,
    candidate_nonce: int,
    sha: int,
    compression: int,
) -> None:
    if not (
        reference_nonce == GENESIS_NONCE
        and candidate_nonce == BIT0_CANDIDATE_NONCE
        and sha == 1
        and compression == 1
    ):
        return
    round_number = prediction.identity["round"]
    if round_number == 4:
        expected = {
            "reference_w": 0x1DAC2B7C,
            "candidate_w": 0x1CAC2B7C,
            "reference_temp1": 0x0A94A2A8,
            "candidate_temp1": 0x0994A2A8,
            "reference_new_a": 0x98610C20,
            "candidate_new_a": 0x97610C20,
            "reference_new_e": 0xC7253CDB,
            "candidate_new_e": 0xC6253CDB,
        }
        observed = {
            "reference_w": prediction.external_w.reference_abs,
            "candidate_w": prediction.external_w.predicted_candidate_abs,
            "reference_temp1": prediction.operations["temp1"].value.reference_abs,
            "candidate_temp1": prediction.operations["temp1"].value.predicted_candidate_abs,
            "reference_new_a": prediction.operations["new_a"].value.reference_abs,
            "candidate_new_a": prediction.operations["new_a"].value.predicted_candidate_abs,
            "reference_new_e": prediction.operations["new_e"].value.reference_abs,
            "candidate_new_e": prediction.operations["new_e"].value.predicted_candidate_abs,
        }
        require(observed == expected, "round 4 predictive sanity check failed")
        require(
            prediction.external_w.xor_delta == 0x01000000
            and prediction.external_w.modular_delta == 0xFF000000
            and signed32(prediction.external_w.modular_delta) == -16777216,
            "round 4 external W dual-domain sanity check failed",
        )
    if 5 <= round_number <= 18:
        require(
            prediction.external_w.predicted_candidate_abs == prediction.external_w.reference_abs,
            f"round {round_number}: expected identical W in Genesis bit-0 window",
        )


def route_usage_template() -> dict[str, dict[str, int]]:
    return {
        family: {route_name: 0 for route_name in ROUTE_NAMES}
        for family in ("Sigma", "Boolean", "Addition")
    }


def csv_text(rounds: Sequence[dict[str, Any]]) -> str:
    fieldnames = [
        "sha",
        "compression",
        "round",
        "input_state_hamming",
        "output_state_hamming",
        "w_hamming",
        "sum0_hamming",
        "sum1_hamming",
        "choice_hamming",
        "majority_hamming",
        "temp1_hamming",
        "temp2_hamming",
        "new_a_hamming",
        "new_e_hamming",
        "sum0_route",
        "sum1_route",
        "choice_route",
        "majority_route",
        "temp1_route",
        "temp2_route",
        "new_a_route",
        "new_e_route",
        "zero_delta_shortcut_count",
        "ROTR32_count",
        "SHR32_count",
        "XOR32_count",
        "AND32_count",
        "NOT32_count",
        "ADD32_count",
        "SUB32_count",
        "hybrid_dual_tracking_word_ops",
        "direct_dual_tracking_word_ops",
        "baseline_sha_round_core_word_ops",
        "hybrid_vs_baseline_core_ratio",
        "hybrid_vs_direct_dual_tracking_ratio",
        "oracle_validation_passed",
    ]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for round_record in rounds:
        operations = round_record["operations"]
        costs = round_record["cost_summary"]
        counts = costs["word_operation_counts"]
        row: dict[str, Any] = {
            "sha": round_record["identity"]["sha"],
            "compression": round_record["identity"]["compression"],
            "round": round_record["identity"]["round"],
            "input_state_hamming": round_record["diffusion_cross_check"]["input_state_hamming"],
            "output_state_hamming": round_record["diffusion_cross_check"]["output_state_hamming"],
            "w_hamming": round_record["external_w"]["xor_hamming"],
            "zero_delta_shortcut_count": costs["zero_delta_shortcut_count"],
            "hybrid_dual_tracking_word_ops": costs["hybrid_dual_tracking_word_ops"],
            "direct_dual_tracking_word_ops": costs["direct_dual_tracking_word_ops"],
            "baseline_sha_round_core_word_ops": costs["baseline_sha_round_core_word_ops"],
            "hybrid_vs_baseline_core_ratio": costs["hybrid_vs_baseline_core_ratio"],
            "hybrid_vs_direct_dual_tracking_ratio": costs[
                "hybrid_vs_direct_dual_tracking_ratio"
            ],
            "oracle_validation_passed": round_record["oracle_validation"][
                "oracle_validation_passed"
            ],
        }
        for name in operations:
            row[f"{name}_hamming"] = operations[name]["xor_hamming"]
            row[f"{name}_route"] = operations[name]["chosen_route"]
        for operation in WORD_OPERATIONS:
            row[f"{operation}_count"] = counts[operation]
        writer.writerow(row)
    return stream.getvalue()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Predict SHA-256 rounds with hybrid XOR/modular differential propagation."
    )
    parser.add_argument(
        "--trajectories",
        type=Path,
        default=Path("results/research_nonce_trajectories.json"),
    )
    parser.add_argument(
        "--diffusion", type=Path, default=Path("results/research_nonce_diffusion.json")
    )
    parser.add_argument("--reference-nonce", type=int, default=GENESIS_NONCE)
    parser.add_argument("--candidate-nonce", type=int, default=BIT0_CANDIDATE_NONCE)
    parser.add_argument("--sha", type=int, default=1)
    parser.add_argument("--compression", type=int, default=1)
    parser.add_argument("--round-start", type=int, default=4)
    parser.add_argument("--round-end", type=int, default=18)
    parser.add_argument(
        "--output-prefix", type=Path, default=Path("results/research_dual_domain_bit0")
    )
    parser.add_argument(
        "--allow-recorded-candidate-bootstrap",
        action="store_true",
        help="explicitly allow the initial candidate BEFORE state as an arbitrary-start bootstrap",
    )
    return parser.parse_args(argv)


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    require(1 <= args.round_start <= 64, "--round-start must be in 1..64")
    require(1 <= args.round_end <= 64, "--round-end must be in 1..64")
    require(args.round_start <= args.round_end, "--round-start must not exceed --round-end")
    require(args.sha >= 1, "--sha must be positive")
    require(args.compression >= 0, "--compression must be non-negative")
    trajectories_data = read_json(args.trajectories)
    diffusion_data = read_json(args.diffusion)
    require(isinstance(trajectories_data, dict), "trajectories JSON root must be an object")
    require(isinstance(diffusion_data, dict), "diffusion JSON root must be an object")
    require(
        trajectories_data.get("reference_nonce") == args.reference_nonce,
        "trajectories reference_nonce differs from CLI",
    )
    require(
        diffusion_data.get("reference_nonce") == args.reference_nonce,
        "diffusion reference_nonce differs from CLI",
    )
    reference = find_trajectory(trajectories_data, args.reference_nonce, "reference")
    candidate = find_trajectory(trajectories_data, args.candidate_nonce, "candidate")
    comparison = find_comparison(diffusion_data, args.candidate_nonce)
    require(reference is not candidate, "reference and candidate trajectories must differ")
    require(reference.get("final_hash") == GENESIS_HASH, "reference Genesis hash mismatch")
    require(diffusion_data.get("reference_hash") == GENESIS_HASH, "diffusion Genesis hash mismatch")
    is_bit0_pair = (
        args.reference_nonce == GENESIS_NONCE
        and args.candidate_nonce == BIT0_CANDIDATE_NONCE
    )
    if is_bit0_pair:
        require(args.candidate_nonce - args.reference_nonce == -1, "candidate nonce delta is not -1")
        require(args.candidate_nonce == (args.reference_nonce ^ 1), "candidate is not bit-0 flip")
        validate_bit0_metadata(candidate, comparison)
    reference_compression = find_compression(reference, args.sha, args.compression, "reference")
    candidate_compression = find_compression(candidate, args.sha, args.compression, "candidate")
    oracle = CandidateOracle(candidate_compression)
    round_numbers = list(range(args.round_start, args.round_end + 1))
    first_reference_round = find_round(reference_compression, args.round_start, "reference")
    strict_start = (
        is_bit0_pair
        and args.sha == 1
        and args.compression == 1
        and args.round_start == 4
    )
    predicted_state, bootstrapped = initial_prediction_state(
        first_reference_round,
        oracle,
        sha=args.sha,
        compression=args.compression,
        round_start=args.round_start,
        strict_genesis_bit0_start=strict_start,
        allow_recorded_candidate_bootstrap=args.allow_recorded_candidate_bootstrap,
    )
    analyzed_rounds: list[dict[str, Any]] = []
    route_usage = route_usage_template()
    domain_conversions: Counter[str] = Counter()
    all_word_counts: Counter[str] = Counter({operation: 0 for operation in WORD_OPERATIONS})
    total_zero_shortcuts = 0
    total_oracle_values = 0
    previous_reference_after: dict[str, int] | None = None
    for round_number in round_numbers:
        reference_round = find_round(reference_compression, round_number, "reference")
        if previous_reference_after is not None:
            current_reference_before = state_words(
                reference_round, "before", f"reference round {round_number}"
            )
            require(
                current_reference_before == previous_reference_after,
                f"round {round_number}: reference trajectory is discontinuous",
            )
        require(
            schedule_word(reference_compression, round_number, "reference")
            == word(reference_round.get("message", {}).get("w"), f"reference round {round_number}.w"),
            f"round {round_number}: reference W differs from schedule",
        )
        candidate_w = oracle.external_w(round_number)
        prediction = predict_round(
            reference_round,
            predicted_state,
            candidate_w,
            sha=args.sha,
            compression=args.compression,
            round_number=round_number,
        )
        default_sanity_checks(
            prediction,
            args.reference_nonce,
            args.candidate_nonce,
            args.sha,
            args.compression,
        )
        oracle_validation = oracle.validate_round(prediction, candidate_w)
        diffusion_round = find_diffusion_round(
            comparison, args.sha, args.compression, round_number
        )
        diffusion_validation = validate_diffusion(prediction, diffusion_round)
        analyzed = prediction.as_dict(oracle_validation, diffusion_validation)
        analyzed_rounds.append(analyzed)
        for operation in prediction.operations.values():
            route_usage[operation.family][operation.chosen_route] += 1
        costs = prediction.cost_summary
        total_zero_shortcuts += costs["zero_delta_shortcut_count"]
        domain_conversions.update(costs["domain_conversion_counts"])
        all_word_counts.update(costs["word_operation_counts"])
        total_oracle_values += oracle_validation["validated_value_count"]
        predicted_state = prediction.output_state
        previous_reference_after = prediction.reference_components["after"]
    candidate_hash = candidate.get("final_hash")
    require(
        comparison.get("final_hash") == candidate_hash,
        "candidate final hash differs between trajectories and diffusion",
    )
    signature = inspect.signature(predict_round)
    forbidden_parameters = {"candidate", "candidate_round", "oracle"}
    require(
        forbidden_parameters.isdisjoint(signature.parameters),
        "predict_round has an oracle-bearing parameter",
    )
    round_count = len(analyzed_rounds)
    baseline_total = round_count * BASELINE_CORE_PER_ROUND
    direct_dual_total = round_count * DIRECT_DUAL_PER_ROUND
    hybrid_total = sum(
        item["cost_summary"]["hybrid_dual_tracking_word_ops"] for item in analyzed_rounds
    )
    is_default_experiment = (
        strict_start and args.round_start == 4 and args.round_end == 18 and not bootstrapped
    )
    if is_default_experiment:
        require(round_count == 15, "default experiment did not produce 15 rounds")
        require(baseline_total == 390, "default baseline total sanity check failed")
        require(direct_dual_total == 630, "default direct-dual total sanity check failed")
    report = {
        "schema_version": 1,
        "analysis": "dual_domain_predictive_differential",
        "metadata": {
            "experiment": "experiment_2_hybrid_xor_modulo_2_32",
            "scope": "sha256_compression_round_core",
            "trajectories_source": str(args.trajectories),
            "diffusion_source": str(args.diffusion),
            "reference_nonce": args.reference_nonce,
            "candidate_nonce": args.candidate_nonce,
            "reference_hash": reference.get("final_hash"),
            "candidate_hash_after_oracle_validation": candidate_hash,
            "sha": args.sha,
            "compression": args.compression,
            "round_start": args.round_start,
            "round_end": args.round_end,
            "round_numbering": "human_1_to_64",
            "difference_direction": "candidate_minus_reference",
            "message_schedule_generation_excluded": True,
            "external_candidate_w_allowed": True,
            "external_w_is_only_pre_prediction_candidate_round_value": True,
            "prediction_bootstrapped_from_candidate_state": bootstrapped,
            "default_experiment": is_default_experiment,
        },
        "cost_model": {
            "kind": "canonical_structural_word_operation_count",
            "primary_word_operations": list(WORD_OPERATIONS),
            "each_primary_word_operation_cost": 1,
            "baseline_sha_round_core_breakdown": {
                "sum0": 5,
                "sum1": 5,
                "choice": 4,
                "majority": 5,
                "temp1": 4,
                "temp2": 1,
                "new_a": 1,
                "new_e": 1,
            },
            "baseline_sha_round_core_word_ops": BASELINE_CORE_PER_ROUND,
            "direct_dual_tracking_breakdown": {
                "sum0": 7,
                "sum1": 7,
                "choice": 6,
                "majority": 7,
                "temp1": 6,
                "temp2": 3,
                "new_a": 3,
                "new_e": 3,
            },
            "direct_dual_tracking_word_ops": DIRECT_DUAL_PER_ROUND,
            "external_w_domain_materialization_policy": (
                "nonzero external W pays ABS->XOR plus ABS->MOD; exact equality reuses zero deltas"
            ),
            "validation_arithmetic_excluded_from_primary_count": True,
            "reference_word_reads_definition": (
                "8 BEFORE words + reference W + derived K + 8 reference operation outputs"
            ),
        },
        "limitations": {
            "message_schedule_generation_excluded": True,
            "feed_forward_excluded": True,
            "second_sha_excluded_from_default_experiment": True,
            "reference_trajectory_precomputation_cost_excluded": True,
            "word_operation_cost_model_is_not_hardware_timing": True,
            "memory_access_cost_excluded_from_primary_word_op_count": True,
            "branch_cost_excluded_from_primary_word_op_count": True,
            "hybrid_route_selection_is_local_not_globally_circuit_optimal": True,
            "hardware_specific_instruction_fusion_excluded": True,
            "python_runtime_overhead_excluded": True,
            "oracle_validation_cost_excluded": True,
            "no_cryptanalytic_shortcut_claimed": True,
        },
        "validation": {
            "predictive_oracle_separation": True,
            "predict_round_signature": str(signature),
            "predict_round_candidate_round_parameter_absent": True,
            "prediction_functions": [
                "predict_sigma",
                "predict_boolean",
                "predict_addition",
                "predict_round",
            ],
            "candidate_round_access_boundary": [
                "CandidateOracle.external_w (authorized W only)",
                "CandidateOracle.bootstrap_before (explicit opt-in only)",
                "CandidateOracle.validate_round (post-prediction oracle phase)",
            ],
            "non_interference_claim": "architectural review, not a formal proof",
            "all_predictions_match_oracle": True,
            "oracle_validated_value_count": total_oracle_values,
            "diffusion_cross_check": True,
            "exact_sigma_xor_identities": True,
            "exact_boolean_xor_identities": True,
            "exact_modular_addition_identities": True,
            "derived_k_candidate_equals_reference": True,
            "round_state_continuity": True,
            "genesis_bit0_labels": True if is_bit0_pair else "not_applicable",
            "round4_predictive_sanity": True if strict_start else "not_applicable",
        },
        "rounds": analyzed_rounds,
        "summary": {
            "round_count": round_count,
            "rounds": round_numbers,
            "baseline_core_total_word_ops": baseline_total,
            "direct_dual_tracking_total_word_ops": direct_dual_total,
            "hybrid_dual_tracking_total_word_ops": hybrid_total,
            "hybrid_vs_baseline_core_total_ratio": hybrid_total / baseline_total,
            "hybrid_vs_direct_dual_tracking_total_ratio": hybrid_total / direct_dual_total,
            "total_zero_delta_shortcuts": total_zero_shortcuts,
            "route_usage_counts": route_usage,
            "domain_conversion_counts": dict(sorted(domain_conversions.items())),
            "domain_conversion_count": sum(domain_conversions.values()),
            "primary_word_operation_totals": {
                operation: all_word_counts[operation] for operation in WORD_OPERATIONS
            },
            "oracle_validated_value_count": total_oracle_values,
            "all_predictions_match_oracle": True,
            "diffusion_cross_check": True,
            "scientific_scenario": (
                "A"
                if hybrid_total < baseline_total
                else "B"
                if hybrid_total < direct_dual_total
                else "C"
            ),
        },
    }
    return report, csv_text(analyzed_rounds)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output_json = Path(f"{args.output_prefix}.json")
    output_csv = Path(f"{args.output_prefix}.csv")
    input_paths = {args.trajectories.resolve(), args.diffusion.resolve()}
    require(output_json.resolve() not in input_paths, "JSON output would overwrite an input")
    require(output_csv.resolve() not in input_paths, "CSV output would overwrite an input")
    require(output_json.resolve() != output_csv.resolve(), "JSON and CSV outputs collide")
    report, csv_report = build_report(args)
    json_report = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json_report, encoding="utf-8")
    output_csv.write_text(csv_report, encoding="utf-8", newline="")
    summary = report["summary"]
    print(f"[DUAL] reference={args.reference_nonce} candidate={args.candidate_nonce}")
    print(
        f"[DUAL] SHA{args.sha} compression={args.compression} "
        f"rounds={args.round_start}..{args.round_end}"
    )
    print("[DUAL] predictive oracle separation enabled")
    print(f"[DUAL] {summary['round_count']} rounds predicted and validated")
    print("[DUAL] diffusion cross-check OK")
    print(f"[DUAL] hybrid word ops={summary['hybrid_dual_tracking_total_word_ops']}")
    print(f"[DUAL] baseline core word ops={summary['baseline_core_total_word_ops']}")
    print(
        "[DUAL] direct dual tracking word ops="
        f"{summary['direct_dual_tracking_total_word_ops']}"
    )
    print(f"[DUAL] reports saved: {output_json}, {output_csv}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AnalysisError, OSError) as exc:
        print(f"[DUAL] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
