# tools\research_causal_analysis.py
"""Exact local causal analysis of recorded SHA-256 differential trajectories."""

from __future__ import annotations

import argparse
import csv
import io
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


MASK32 = 0xFFFFFFFF
WORD_BITS = 32
REGISTERS = ("a", "b", "c", "d", "e", "f", "g", "h")
GENESIS_NONCE = 2083236893
BIT0_CANDIDATE_NONCE = 2083236892
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


class AnalysisError(RuntimeError):
    """Raised when input data or a causal invariant is inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalysisError(message)


def word(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise AnalysisError(f"{context}: boolean is not a valid 32-bit word")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 16)
        except ValueError as exc:
            raise AnalysisError(f"{context}: invalid hexadecimal word {value!r}") from exc
    else:
        raise AnalysisError(f"{context}: expected integer or hexadecimal string")
    require(0 <= parsed <= MASK32, f"{context}: value is outside uint32")
    return parsed


def hex32(value: int) -> str:
    return f"{value & MASK32:08x}"


def hamming(value: int) -> int:
    return (value & MASK32).bit_count()


def word_difference(reference_value: int, candidate_value: int) -> dict[str, Any]:
    reference_value &= MASK32
    candidate_value &= MASK32
    xor_delta = reference_value ^ candidate_value
    exact = candidate_value - reference_value
    mod32 = exact & MASK32
    signed32 = mod32 if mod32 < 0x80000000 else mod32 - 0x100000000
    return {
        "direction": "candidate_minus_reference",
        "reference_hex": hex32(reference_value),
        "candidate_hex": hex32(candidate_value),
        "xor_delta_hex": hex32(xor_delta),
        "xor_hamming": hamming(xor_delta),
        "candidate_minus_reference_exact": exact,
        "candidate_minus_reference_mod32_hex": hex32(mod32),
        "candidate_minus_reference_signed32": signed32,
    }


def rotr32(value: int, amount: int) -> int:
    amount %= WORD_BITS
    return ((value >> amount) | (value << (WORD_BITS - amount))) & MASK32


def shr32(value: int, amount: int) -> int:
    return (value & MASK32) >> amount


def big_sigma0(value: int) -> int:
    return rotr32(value, 2) ^ rotr32(value, 13) ^ rotr32(value, 22)


def big_sigma1(value: int) -> int:
    return rotr32(value, 6) ^ rotr32(value, 11) ^ rotr32(value, 25)


def small_sigma0(value: int) -> int:
    return rotr32(value, 7) ^ rotr32(value, 18) ^ shr32(value, 3)


def small_sigma1(value: int) -> int:
    return rotr32(value, 17) ^ rotr32(value, 19) ^ shr32(value, 10)


def choice_word(e: int, f: int, g: int) -> int:
    return ((e & f) ^ ((~e) & g)) & MASK32


def majority_word(a: int, b: int, c: int) -> int:
    return ((a & b) ^ (a & c) ^ (b & c)) & MASK32


def choice_bit(bits: Sequence[int]) -> int:
    e, f, g = bits
    return (e & f) ^ ((e ^ 1) & g)


def majority_bit(bits: Sequence[int]) -> int:
    a, b, c = bits
    return (a & b) ^ (a & c) ^ (b & c)


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


def find_comparison(data: dict[str, Any], nonce: int) -> dict[str, Any]:
    comparisons = data.get("comparisons")
    require(isinstance(comparisons, list), "diffusion input has no comparisons array")
    return find_unique(
        comparisons,
        lambda record: record.get("nonce") == nonce,
        f"diffusion comparison for candidate nonce {nonce}",
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


def find_round(
    compression: dict[str, Any], round_number: int, role: str
) -> dict[str, Any]:
    rounds = compression.get("rounds")
    require(isinstance(rounds, list), f"{role} compression has no rounds array")
    return find_unique(
        rounds,
        lambda record: isinstance(record.get("identity"), dict)
        and record["identity"].get("round") == round_number,
        f"{role} round {round_number}",
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


def state_words(round_record: dict[str, Any], phase: str, context: str) -> dict[str, int]:
    state = round_record.get(phase)
    require(isinstance(state, dict), f"{context}: missing {phase} state")
    return {
        register: word(state.get(register), f"{context}.{phase}.{register}")
        for register in REGISTERS
    }


def state_difference(
    reference_state: dict[str, int], candidate_state: dict[str, int]
) -> dict[str, Any]:
    registers = {
        register: word_difference(reference_state[register], candidate_state[register])
        for register in REGISTERS
    }
    return {
        "registers": registers,
        "total_hamming": sum(item["xor_hamming"] for item in registers.values()),
    }


def recorded_word(container: dict[str, Any], key: str, context: str) -> int:
    require(key in container, f"{context}: missing {key}")
    return word(container[key], f"{context}.{key}")


def validate_recorded_primitive(
    round_record: dict[str, Any], before: dict[str, int], context: str
) -> dict[str, int]:
    sigma0_record = round_record.get("large_sigma0")
    sigma1_record = round_record.get("large_sigma1")
    functions = round_record.get("functions")
    require(isinstance(sigma0_record, dict), f"{context}: missing large_sigma0")
    require(isinstance(sigma1_record, dict), f"{context}: missing large_sigma1")
    require(isinstance(functions, dict), f"{context}: missing functions")

    expected = {
        "rotr2_a": rotr32(before["a"], 2),
        "rotr13_a": rotr32(before["a"], 13),
        "rotr22_a": rotr32(before["a"], 22),
        "sum0": big_sigma0(before["a"]),
        "rotr6_e": rotr32(before["e"], 6),
        "rotr11_e": rotr32(before["e"], 11),
        "rotr25_e": rotr32(before["e"], 25),
        "sum1": big_sigma1(before["e"]),
        "choice": choice_word(before["e"], before["f"], before["g"]),
        "majority": majority_word(before["a"], before["b"], before["c"]),
    }
    observed = {
        name: recorded_word(sigma0_record, name, f"{context}.large_sigma0")
        for name in ("rotr2_a", "rotr13_a", "rotr22_a", "sum0")
    }
    observed.update(
        {
            name: recorded_word(sigma1_record, name, f"{context}.large_sigma1")
            for name in ("rotr6_e", "rotr11_e", "rotr25_e", "sum1")
        }
    )
    observed.update(
        {
            name: recorded_word(functions, name, f"{context}.functions")
            for name in ("choice", "majority")
        }
    )
    for name, expected_value in expected.items():
        require(
            observed[name] == expected_value,
            f"{context}: recorded {name}={hex32(observed[name])}, expected {hex32(expected_value)}",
        )
    return observed


def local_boolean_certificate(
    actual_reference_bits: Sequence[int],
    delta_bits: Sequence[int],
    function: Callable[[Sequence[int]], int],
) -> tuple[int, ...]:
    actual_output_delta = function(
        tuple(bit ^ delta for bit, delta in zip(actual_reference_bits, delta_bits))
    ) ^ function(actual_reference_bits)
    variable_indices = tuple(range(len(actual_reference_bits)))
    for size in range(len(variable_indices) + 1):
        for subset in itertools.combinations(variable_indices, size):
            valid = True
            for assignment in itertools.product((0, 1), repeat=len(variable_indices)):
                if any(assignment[index] != actual_reference_bits[index] for index in subset):
                    continue
                candidate = tuple(
                    bit ^ delta for bit, delta in zip(assignment, delta_bits)
                )
                if (function(candidate) ^ function(assignment)) != actual_output_delta:
                    valid = False
                    break
            if valid:
                return subset
    raise AnalysisError("internal error: no Boolean context certificate found")


def analyze_boolean_primitive(
    name: str,
    variable_names: Sequence[str],
    reference_values: Sequence[int],
    candidate_values: Sequence[int],
    function_bit: Callable[[Sequence[int]], int],
    function_word: Callable[..., int],
    recorded_reference_output: int,
    recorded_candidate_output: int,
) -> dict[str, Any]:
    calculated_reference = function_word(*reference_values)
    calculated_candidate = function_word(*candidate_values)
    require(
        calculated_reference == recorded_reference_output,
        f"{name}: reference output does not match the recorded trajectory",
    )
    require(
        calculated_candidate == recorded_candidate_output,
        f"{name}: candidate output does not match the recorded trajectory",
    )

    bits: list[dict[str, Any]] = []
    by_variable = {variable: 0 for variable in variable_names}
    context_free_positions: list[int] = []
    for bit_index in range(WORD_BITS):
        reference_bits = tuple((value >> bit_index) & 1 for value in reference_values)
        candidate_bits = tuple((value >> bit_index) & 1 for value in candidate_values)
        delta_bits = tuple(
            reference_bit ^ candidate_bit
            for reference_bit, candidate_bit in zip(reference_bits, candidate_bits)
        )
        certificate = local_boolean_certificate(reference_bits, delta_bits, function_bit)
        certificate_names = [variable_names[index] for index in certificate]
        for variable in certificate_names:
            by_variable[variable] += 1
        if not certificate:
            context_free_positions.append(bit_index)
        reference_output_bit = function_bit(reference_bits)
        candidate_output_bit = function_bit(candidate_bits)
        bits.append(
            {
                "bit": bit_index,
                "reference_output_bit": reference_output_bit,
                "candidate_output_bit": candidate_output_bit,
                "delta_output_bit": reference_output_bit ^ candidate_output_bit,
                "input_delta_bits": dict(zip(variable_names, delta_bits)),
                "local_minimal_context_certificate": {
                    "variable_names": certificate_names,
                    "bit_positions": [bit_index for _ in certificate],
                    "actual_reference_values": [reference_bits[index] for index in certificate],
                    "certificate_size": len(certificate),
                },
            }
        )

    difference = word_difference(recorded_reference_output, recorded_candidate_output)
    return {
        "primitive": name,
        "model": "bitwise_local_truth_table_with_known_input_xor_deltas",
        "bits": bits,
        "summary": {
            "output_xor_delta_hex": difference["xor_delta_hex"],
            "output_hamming": difference["xor_hamming"],
            "context_certificate_bits_total": sum(by_variable.values()),
            "context_free_output_bits": len(context_free_positions),
            "context_free_output_bit_positions": context_free_positions,
            "context_certificate_bits_by_variable": by_variable,
        },
    }


def longest_nonzero_run(mask: int) -> int:
    longest = 0
    current = 0
    for bit_index in range(WORD_BITS):
        if (mask >> bit_index) & 1:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def local_addition_certificate(
    actual_reference_bits: Sequence[int],
    delta_bits: Sequence[int],
    reference_carry_in: int,
    candidate_carry_in: int,
) -> tuple[int, ...]:
    actual_candidate_bits = tuple(
        bit ^ delta for bit, delta in zip(actual_reference_bits, delta_bits)
    )
    reference_total = reference_carry_in + sum(actual_reference_bits)
    candidate_total = candidate_carry_in + sum(actual_candidate_bits)
    target = (
        (reference_total & 1) ^ (candidate_total & 1),
        reference_total >> 1,
        candidate_total >> 1,
    )
    operand_indices = tuple(range(len(actual_reference_bits)))
    for size in range(len(operand_indices) + 1):
        for subset in itertools.combinations(operand_indices, size):
            valid = True
            for assignment in itertools.product((0, 1), repeat=len(operand_indices)):
                if any(assignment[index] != actual_reference_bits[index] for index in subset):
                    continue
                candidate = tuple(
                    bit ^ delta for bit, delta in zip(assignment, delta_bits)
                )
                possible_reference_total = reference_carry_in + sum(assignment)
                possible_candidate_total = candidate_carry_in + sum(candidate)
                possible = (
                    (possible_reference_total & 1) ^ (possible_candidate_total & 1),
                    possible_reference_total >> 1,
                    possible_candidate_total >> 1,
                )
                if possible != target:
                    valid = False
                    break
            if valid:
                return subset
    raise AnalysisError("internal error: no addition context certificate found")


def extract_recorded_operands(
    record: dict[str, Any], context: str
) -> list[tuple[str, int]]:
    operands = record.get("operands")
    require(isinstance(operands, list), f"{context}: missing operands array")
    extracted: list[tuple[str, int]] = []
    for index, operand in enumerate(operands):
        require(isinstance(operand, dict), f"{context}.operands[{index}]: expected object")
        name = operand.get("name")
        require(isinstance(name, str), f"{context}.operands[{index}]: missing operand name")
        extracted.append((name, word(operand.get("value"), f"{context}.operands[{index}].value")))
    return extracted


def validate_carry_summary(
    record: dict[str, Any],
    carry_out_values: Sequence[int],
    context: str,
) -> None:
    summary = record.get("carry_summary")
    require(isinstance(summary, dict), f"{context}: missing carry_summary")
    nonzero_mask = sum(
        (1 << bit_index) for bit_index, carry in enumerate(carry_out_values) if carry != 0
    )
    expected = {
        "final_carry_value": carry_out_values[-1],
        "max_carry_value": max(carry_out_values),
        "nonzero_carry_count": sum(carry != 0 for carry in carry_out_values),
        "nonzero_carry_mask_hex": hex32(nonzero_mask),
        "longest_nonzero_carry_run": longest_nonzero_run(nonzero_mask),
    }
    for key, expected_value in expected.items():
        require(
            summary.get(key) == expected_value,
            f"{context}: carry summary {key}={summary.get(key)!r}, expected {expected_value!r}",
        )


def analyze_addition(
    name: str,
    reference_record: dict[str, Any],
    candidate_record: dict[str, Any],
    expected_reference_operands: Sequence[tuple[str, int]],
    expected_candidate_operands: Sequence[tuple[str, int]],
    expected_reference_result: int,
    expected_candidate_result: int,
    context: str,
) -> dict[str, Any]:
    reference_operands = extract_recorded_operands(reference_record, f"{context}.reference")
    candidate_operands = extract_recorded_operands(candidate_record, f"{context}.candidate")
    require(
        reference_operands == list(expected_reference_operands),
        f"{context}: reference operands differ from causally derived operands",
    )
    require(
        candidate_operands == list(expected_candidate_operands),
        f"{context}: candidate operands differ from causally derived operands",
    )
    operand_names = [operand_name for operand_name, _ in reference_operands]
    require(
        operand_names == [operand_name for operand_name, _ in candidate_operands],
        f"{context}: operand names differ between trajectories",
    )
    require(len(set(operand_names)) == len(operand_names), f"{context}: duplicate operand name")

    reference_result = word(reference_record.get("result"), f"{context}.reference.result")
    candidate_result = word(candidate_record.get("result"), f"{context}.candidate.result")
    require(reference_result == expected_reference_result, f"{context}: unexpected reference result")
    require(candidate_result == expected_candidate_result, f"{context}: unexpected candidate result")
    require(
        sum(value for _, value in reference_operands) & MASK32 == reference_result,
        f"{context}: reference modular addition validation failed",
    )
    require(
        sum(value for _, value in candidate_operands) & MASK32 == candidate_result,
        f"{context}: candidate modular addition validation failed",
    )

    columns: list[dict[str, Any]] = []
    reference_carry = 0
    candidate_carry = 0
    reconstructed_reference = 0
    reconstructed_candidate = 0
    reference_carry_out_values: list[int] = []
    candidate_carry_out_values: list[int] = []
    context_by_operand = {operand_name: 0 for operand_name in operand_names}
    context_free_columns: list[int] = []
    carry_pair_difference_columns: list[int] = []

    for bit_index in range(WORD_BITS):
        reference_bits = tuple((value >> bit_index) & 1 for _, value in reference_operands)
        candidate_bits = tuple((value >> bit_index) & 1 for _, value in candidate_operands)
        delta_bits = tuple(
            reference_bit ^ candidate_bit
            for reference_bit, candidate_bit in zip(reference_bits, candidate_bits)
        )
        reference_total = reference_carry + sum(reference_bits)
        candidate_total = candidate_carry + sum(candidate_bits)
        reference_result_bit = reference_total & 1
        candidate_result_bit = candidate_total & 1
        reference_carry_out = reference_total >> 1
        candidate_carry_out = candidate_total >> 1
        certificate = local_addition_certificate(
            reference_bits, delta_bits, reference_carry, candidate_carry
        )
        certificate_names = [operand_names[index] for index in certificate]
        for operand_name in certificate_names:
            context_by_operand[operand_name] += 1
        if not certificate:
            context_free_columns.append(bit_index)
        if reference_carry_out != candidate_carry_out:
            carry_pair_difference_columns.append(bit_index)
        reconstructed_reference |= reference_result_bit << bit_index
        reconstructed_candidate |= candidate_result_bit << bit_index
        reference_carry_out_values.append(reference_carry_out)
        candidate_carry_out_values.append(candidate_carry_out)
        columns.append(
            {
                "bit": bit_index,
                "reference_carry_in": reference_carry,
                "candidate_carry_in": candidate_carry,
                "reference_operand_bits": dict(zip(operand_names, reference_bits)),
                "candidate_operand_bits": dict(zip(operand_names, candidate_bits)),
                "operand_delta_bits": dict(zip(operand_names, delta_bits)),
                "reference_column_total": reference_total,
                "candidate_column_total": candidate_total,
                "reference_result_bit": reference_result_bit,
                "candidate_result_bit": candidate_result_bit,
                "result_delta_bit": reference_result_bit ^ candidate_result_bit,
                "reference_carry_out": reference_carry_out,
                "candidate_carry_out": candidate_carry_out,
                "carry_difference_exact": candidate_carry_out - reference_carry_out,
                "local_minimal_context_certificate": {
                    "operand_names": certificate_names,
                    "bit_positions": [bit_index for _ in certificate],
                    "actual_reference_values": [reference_bits[index] for index in certificate],
                    "certificate_size": len(certificate),
                },
            }
        )
        reference_carry = reference_carry_out
        candidate_carry = candidate_carry_out

    require(reconstructed_reference == reference_result, f"{context}: reference bit reconstruction failed")
    require(reconstructed_candidate == candidate_result, f"{context}: candidate bit reconstruction failed")
    validate_carry_summary(reference_record, reference_carry_out_values, f"{context}.reference")
    validate_carry_summary(candidate_record, candidate_carry_out_values, f"{context}.candidate")

    difference = word_difference(reference_result, candidate_result)
    carry_differences = [
        candidate - reference
        for reference, candidate in zip(reference_carry_out_values, candidate_carry_out_values)
    ]
    return {
        "operation": name,
        "operand_order": operand_names,
        "reference_result": hex32(reference_result),
        "candidate_result": hex32(candidate_result),
        "xor_delta": difference["xor_delta_hex"],
        "xor_hamming": difference["xor_hamming"],
        "modular_delta": {
            "direction": "candidate_minus_reference",
            "exact": difference["candidate_minus_reference_exact"],
            "mod32_hex": difference["candidate_minus_reference_mod32_hex"],
            "signed32": difference["candidate_minus_reference_signed32"],
        },
        "columns": columns,
        "summary": {
            "context_certificate_bits_total": sum(context_by_operand.values()),
            "context_certificate_bits_by_operand": context_by_operand,
            "context_free_columns": len(context_free_columns),
            "context_free_column_positions": context_free_columns,
            "columns_with_different_carry_pair": carry_pair_difference_columns,
            "carry_pair_difference_column_count": len(carry_pair_difference_columns),
            "first_carry_pair_difference_bit": (
                carry_pair_difference_columns[0] if carry_pair_difference_columns else None
            ),
            "last_carry_pair_difference_bit": (
                carry_pair_difference_columns[-1] if carry_pair_difference_columns else None
            ),
            "max_absolute_carry_difference": max(abs(value) for value in carry_differences),
            "reference_final_carry": reference_carry,
            "candidate_final_carry": candidate_carry,
        },
    }


def validate_schedule_word(
    compression: dict[str, Any], round_number: int, expected_word: int, context: str
) -> None:
    schedule = compression.get("message_schedule")
    require(isinstance(schedule, dict), f"{context}: missing message_schedule")
    words = schedule.get("words")
    require(isinstance(words, list), f"{context}: missing message schedule words")
    schedule_record = find_unique(
        words,
        lambda record: record.get("round") == round_number,
        f"{context} message schedule round {round_number}",
    )
    schedule_value_key = "w" if "w" in schedule_record else "result_w"
    require(
        schedule_value_key in schedule_record,
        f"{context}: message schedule round {round_number} has no word value",
    )
    schedule_word = word(
        schedule_record[schedule_value_key],
        f"{context}.message_schedule.round{round_number}.{schedule_value_key}",
    )
    require(schedule_word == expected_word, f"{context}: round W differs from message schedule")


def validate_diffusion_cross_check(
    diffusion_round: dict[str, Any],
    recomputed: dict[str, int],
    round_number: int,
) -> None:
    direct_metrics = (
        "w_hamming",
        "rotr2_a_hamming",
        "rotr13_a_hamming",
        "rotr22_a_hamming",
        "sum0_hamming",
        "rotr6_e_hamming",
        "rotr11_e_hamming",
        "rotr25_e_hamming",
        "sum1_hamming",
        "choice_hamming",
        "majority_hamming",
        "temp1_hamming",
        "temp2_hamming",
    )
    for metric in direct_metrics:
        require(
            diffusion_round.get(metric) == recomputed[metric],
            f"round {round_number}: diffusion {metric}={diffusion_round.get(metric)!r}, "
            f"recomputed={recomputed[metric]}",
        )
    for phase, metric in (("before", "input_state_hamming"), ("after", "output_state_hamming")):
        phase_record = diffusion_round.get(phase)
        require(isinstance(phase_record, dict), f"round {round_number}: diffusion missing {phase}")
        require(
            phase_record.get("total_hamming") == recomputed[metric],
            f"round {round_number}: diffusion {phase}.total_hamming="
            f"{phase_record.get('total_hamming')!r}, recomputed={recomputed[metric]}",
        )
        for register in REGISTERS:
            register_metric = f"{phase}_{register}_hamming"
            require(
                phase_record.get(register) == recomputed[register_metric],
                f"round {round_number}: diffusion {phase}.{register} mismatch",
            )


def validate_bit0_labels(
    trajectory: dict[str, Any], comparison: dict[str, Any]
) -> None:
    def validate_labels(labels: Any, context: str) -> None:
        require(isinstance(labels, list), f"{context}: labels are missing")
        bit_labels = [
            label
            for label in labels
            if isinstance(label, dict)
            and label.get("kind") == "single_bit_flip"
            and label.get("bit") == 0
        ]
        neighbor_labels = [
            label
            for label in labels
            if isinstance(label, dict)
            and label.get("kind") == "neighbor"
            and label.get("delta") == -1
        ]
        require(len(bit_labels) == 1, f"{context}: expected one single_bit_flip bit=0 label")
        require(len(neighbor_labels) == 1, f"{context}: expected one neighbor delta=-1 label")
        require(bit_labels[0].get("w3_hamming") == 1, f"{context}: w3_hamming is not 1")
        require(bit_labels[0].get("w3_changed_bit") == 24, f"{context}: w3_changed_bit is not 24")

    validate_labels(trajectory.get("labels"), "candidate trajectory")
    validate_labels(comparison.get("labels"), "candidate diffusion comparison")
    changes = trajectory.get("single_bit_w3_changes")
    require(isinstance(changes, list), "candidate trajectory: single_bit_w3_changes missing")
    matches = [
        change
        for change in changes
        if isinstance(change, dict)
        and change.get("nonce_bit") == 0
        and change.get("w3_hamming") == 1
        and change.get("w3_changed_bit") == 24
    ]
    require(len(matches) == 1, "candidate trajectory: bit-0 W3 change metadata mismatch")


def transfer_analysis(
    reference_before: dict[str, int],
    candidate_before: dict[str, int],
    reference_after: dict[str, int],
    candidate_after: dict[str, int],
    reference_round: dict[str, Any],
    candidate_round: dict[str, Any],
    context: str,
) -> dict[str, Any]:
    transfers = (
        ("b", "a", "new_b_from_old_a"),
        ("c", "b", "new_c_from_old_b"),
        ("d", "c", "new_d_from_old_c"),
        ("f", "e", "new_f_from_old_e"),
        ("g", "f", "new_g_from_old_f"),
        ("h", "g", "new_h_from_old_g"),
    )
    reference_record = reference_round.get("state_construction", {}).get("transfers")
    candidate_record = candidate_round.get("state_construction", {}).get("transfers")
    require(isinstance(reference_record, dict), f"{context}: reference transfers missing")
    require(isinstance(candidate_record, dict), f"{context}: candidate transfers missing")
    output: dict[str, Any] = {}
    for target, source, recorded_name in transfers:
        reference_value = reference_before[source]
        candidate_value = candidate_before[source]
        require(reference_after[target] == reference_value, f"{context}: reference {target} transfer failed")
        require(candidate_after[target] == candidate_value, f"{context}: candidate {target} transfer failed")
        require(
            word(reference_record.get(recorded_name), f"{context}.reference.{recorded_name}")
            == reference_value,
            f"{context}: reference recorded transfer {recorded_name} mismatch",
        )
        require(
            word(candidate_record.get(recorded_name), f"{context}.candidate.{recorded_name}")
            == candidate_value,
            f"{context}: candidate recorded transfer {recorded_name} mismatch",
        )
        output[recorded_name] = {
            "source_register": source,
            "target_register": target,
            "difference": word_difference(reference_value, candidate_value),
            "absolute_context_bits_required": 0,
        }
    return output


def analyze_round(
    round_number: int,
    sha: int,
    compression_number: int,
    reference_compression: dict[str, Any],
    candidate_compression: dict[str, Any],
    diffusion_comparison: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    context = f"SHA{sha} compression {compression_number} round {round_number}"
    reference_round = find_round(reference_compression, round_number, "reference")
    candidate_round = find_round(candidate_compression, round_number, "candidate")
    diffusion_round = find_diffusion_round(
        diffusion_comparison, sha, compression_number, round_number
    )
    expected_identity = {"compression": compression_number, "round": round_number, "sha": sha}
    require(reference_round.get("identity") == expected_identity, f"{context}: bad reference identity")
    require(candidate_round.get("identity") == expected_identity, f"{context}: bad candidate identity")

    reference_before = state_words(reference_round, "before", f"{context}.reference")
    candidate_before = state_words(candidate_round, "before", f"{context}.candidate")
    reference_after = state_words(reference_round, "after", f"{context}.reference")
    candidate_after = state_words(candidate_round, "after", f"{context}.candidate")
    input_difference = state_difference(reference_before, candidate_before)
    output_difference = state_difference(reference_after, candidate_after)

    reference_w = word(reference_round.get("message", {}).get("w"), f"{context}.reference.w")
    candidate_w = word(candidate_round.get("message", {}).get("w"), f"{context}.candidate.w")
    validate_schedule_word(reference_compression, round_number, reference_w, f"{context}.reference")
    validate_schedule_word(candidate_compression, round_number, candidate_w, f"{context}.candidate")
    message_difference = word_difference(reference_w, candidate_w)

    reference_primitives = validate_recorded_primitive(reference_round, reference_before, f"{context}.reference")
    candidate_primitives = validate_recorded_primitive(candidate_round, candidate_before, f"{context}.candidate")

    sum0_difference = word_difference(reference_primitives["sum0"], candidate_primitives["sum0"])
    sum1_difference = word_difference(reference_primitives["sum1"], candidate_primitives["sum1"])
    sum0_linearity = (
        reference_primitives["sum0"] ^ candidate_primitives["sum0"]
        == big_sigma0(reference_before["a"] ^ candidate_before["a"])
    )
    sum1_linearity = (
        reference_primitives["sum1"] ^ candidate_primitives["sum1"]
        == big_sigma1(reference_before["e"] ^ candidate_before["e"])
    )
    require(sum0_linearity, f"{context}: Sigma0 XOR-linearity identity failed")
    require(sum1_linearity, f"{context}: Sigma1 XOR-linearity identity failed")

    choice = analyze_boolean_primitive(
        "Ch",
        ("e", "f", "g"),
        tuple(reference_before[name] for name in ("e", "f", "g")),
        tuple(candidate_before[name] for name in ("e", "f", "g")),
        choice_bit,
        choice_word,
        reference_primitives["choice"],
        candidate_primitives["choice"],
    )
    majority = analyze_boolean_primitive(
        "Maj",
        ("a", "b", "c"),
        tuple(reference_before[name] for name in ("a", "b", "c")),
        tuple(candidate_before[name] for name in ("a", "b", "c")),
        majority_bit,
        majority_word,
        reference_primitives["majority"],
        candidate_primitives["majority"],
    )

    reference_k = word(reference_round.get("derived_k"), f"{context}.reference.derived_k")
    candidate_k = word(candidate_round.get("derived_k"), f"{context}.candidate.derived_k")
    require(reference_k == candidate_k, f"{context}: derived_k differs between trajectories")

    reference_temp1_record = reference_round.get("temp1")
    candidate_temp1_record = candidate_round.get("temp1")
    reference_temp2_record = reference_round.get("temp2")
    candidate_temp2_record = candidate_round.get("temp2")
    require(isinstance(reference_temp1_record, dict), f"{context}: reference temp1 missing")
    require(isinstance(candidate_temp1_record, dict), f"{context}: candidate temp1 missing")
    require(isinstance(reference_temp2_record, dict), f"{context}: reference temp2 missing")
    require(isinstance(candidate_temp2_record, dict), f"{context}: candidate temp2 missing")
    reference_temp1 = word(reference_temp1_record.get("result"), f"{context}.reference.temp1.result")
    candidate_temp1 = word(candidate_temp1_record.get("result"), f"{context}.candidate.temp1.result")
    reference_temp2 = word(reference_temp2_record.get("result"), f"{context}.reference.temp2.result")
    candidate_temp2 = word(candidate_temp2_record.get("result"), f"{context}.candidate.temp2.result")

    temp1 = analyze_addition(
        "temp1",
        reference_temp1_record,
        candidate_temp1_record,
        (
            ("h", reference_before["h"]),
            ("sum1", reference_primitives["sum1"]),
            ("choice", reference_primitives["choice"]),
            ("derived_k", reference_k),
            ("w", reference_w),
        ),
        (
            ("h", candidate_before["h"]),
            ("sum1", candidate_primitives["sum1"]),
            ("choice", candidate_primitives["choice"]),
            ("derived_k", candidate_k),
            ("w", candidate_w),
        ),
        reference_temp1,
        candidate_temp1,
        f"{context}.temp1",
    )
    temp2 = analyze_addition(
        "temp2",
        reference_temp2_record,
        candidate_temp2_record,
        (("sum0", reference_primitives["sum0"]), ("majority", reference_primitives["majority"])),
        (("sum0", candidate_primitives["sum0"]), ("majority", candidate_primitives["majority"])),
        reference_temp2,
        candidate_temp2,
        f"{context}.temp2",
    )

    reference_construction = reference_round.get("state_construction")
    candidate_construction = candidate_round.get("state_construction")
    require(isinstance(reference_construction, dict), f"{context}: reference state_construction missing")
    require(isinstance(candidate_construction, dict), f"{context}: candidate state_construction missing")
    reference_new_a_record = reference_construction.get("new_a")
    candidate_new_a_record = candidate_construction.get("new_a")
    reference_new_e_record = reference_construction.get("new_e")
    candidate_new_e_record = candidate_construction.get("new_e")
    require(isinstance(reference_new_a_record, dict), f"{context}: reference new_a missing")
    require(isinstance(candidate_new_a_record, dict), f"{context}: candidate new_a missing")
    require(isinstance(reference_new_e_record, dict), f"{context}: reference new_e missing")
    require(isinstance(candidate_new_e_record, dict), f"{context}: candidate new_e missing")

    new_a = analyze_addition(
        "new_a",
        reference_new_a_record,
        candidate_new_a_record,
        (("temp1", reference_temp1), ("temp2", reference_temp2)),
        (("temp1", candidate_temp1), ("temp2", candidate_temp2)),
        reference_after["a"],
        candidate_after["a"],
        f"{context}.new_a",
    )
    new_e = analyze_addition(
        "new_e",
        reference_new_e_record,
        candidate_new_e_record,
        (("d", reference_before["d"]), ("temp1", reference_temp1)),
        (("d", candidate_before["d"]), ("temp1", candidate_temp1)),
        reference_after["e"],
        candidate_after["e"],
        f"{context}.new_e",
    )
    transfers = transfer_analysis(
        reference_before,
        candidate_before,
        reference_after,
        candidate_after,
        reference_round,
        candidate_round,
        context,
    )

    recomputed = {
        "w_hamming": message_difference["xor_hamming"],
        "input_state_hamming": input_difference["total_hamming"],
        "output_state_hamming": output_difference["total_hamming"],
        "rotr2_a_hamming": hamming(rotr32(reference_before["a"], 2) ^ rotr32(candidate_before["a"], 2)),
        "rotr13_a_hamming": hamming(rotr32(reference_before["a"], 13) ^ rotr32(candidate_before["a"], 13)),
        "rotr22_a_hamming": hamming(rotr32(reference_before["a"], 22) ^ rotr32(candidate_before["a"], 22)),
        "sum0_hamming": sum0_difference["xor_hamming"],
        "rotr6_e_hamming": hamming(rotr32(reference_before["e"], 6) ^ rotr32(candidate_before["e"], 6)),
        "rotr11_e_hamming": hamming(rotr32(reference_before["e"], 11) ^ rotr32(candidate_before["e"], 11)),
        "rotr25_e_hamming": hamming(rotr32(reference_before["e"], 25) ^ rotr32(candidate_before["e"], 25)),
        "sum1_hamming": sum1_difference["xor_hamming"],
        "choice_hamming": choice["summary"]["output_hamming"],
        "majority_hamming": majority["summary"]["output_hamming"],
        "temp1_hamming": temp1["xor_hamming"],
        "temp2_hamming": temp2["xor_hamming"],
    }
    for phase_name, phase_difference in (("before", input_difference), ("after", output_difference)):
        for register in REGISTERS:
            recomputed[f"{phase_name}_{register}_hamming"] = phase_difference["registers"][register]["xor_hamming"]
    validate_diffusion_cross_check(diffusion_round, recomputed, round_number)

    addition_results = {"temp1": temp1, "temp2": temp2, "new_a": new_a, "new_e": new_e}
    round_summary = {
        "round": round_number,
        "w_hamming": message_difference["xor_hamming"],
        "input_state_hamming": input_difference["total_hamming"],
        "sum0_hamming": sum0_difference["xor_hamming"],
        "sum1_hamming": sum1_difference["xor_hamming"],
        "choice_hamming": choice["summary"]["output_hamming"],
        "majority_hamming": majority["summary"]["output_hamming"],
        "temp1_hamming": temp1["xor_hamming"],
        "temp2_hamming": temp2["xor_hamming"],
        "new_a_hamming": new_a["xor_hamming"],
        "new_e_hamming": new_e["xor_hamming"],
        "output_state_hamming": output_difference["total_hamming"],
        "choice_context_certificate_bits": choice["summary"]["context_certificate_bits_total"],
        "majority_context_certificate_bits": majority["summary"]["context_certificate_bits_total"],
        "temp1_context_certificate_bits": temp1["summary"]["context_certificate_bits_total"],
        "temp2_context_certificate_bits": temp2["summary"]["context_certificate_bits_total"],
        "new_a_context_certificate_bits": new_a["summary"]["context_certificate_bits_total"],
        "new_e_context_certificate_bits": new_e["summary"]["context_certificate_bits_total"],
    }
    round_summary["operation_local_context_certificate_bit_count_sum"] = sum(
        round_summary[key]
        for key in (
            "choice_context_certificate_bits",
            "majority_context_certificate_bits",
            "temp1_context_certificate_bits",
            "temp2_context_certificate_bits",
            "new_a_context_certificate_bits",
            "new_e_context_certificate_bits",
        )
    )

    result = {
        "identity": expected_identity,
        "input_state": input_difference,
        "message_w": message_difference,
        "linear_primitives": {
            "sigma0": {
                "input_register": "a",
                "sum0_difference": sum0_difference,
                "xor_linearity_identity_validated": True,
                "absolute_context_bits_required": 0,
            },
            "sigma1": {
                "input_register": "e",
                "sum1_difference": sum1_difference,
                "xor_linearity_identity_validated": True,
                "absolute_context_bits_required": 0,
            },
        },
        "boolean_primitives": {"choice": choice, "majority": majority},
        "additions": addition_results,
        "register_transfers": transfers,
        "output_state": output_difference,
        "round_summary": round_summary,
        "validation": {"diffusion_cross_check": True, "exact_round_arithmetic": True},
    }
    raw = {
        "reference_round": reference_round,
        "candidate_round": candidate_round,
        "reference_before": reference_before,
        "candidate_before": candidate_before,
        "reference_after": reference_after,
        "candidate_after": candidate_after,
        "reference_w": reference_w,
        "candidate_w": candidate_w,
    }
    return result, raw


def validate_continuity(raw_rounds: Sequence[dict[str, Any]], round_numbers: Sequence[int]) -> None:
    for index in range(1, len(raw_rounds)):
        previous = raw_rounds[index - 1]
        current = raw_rounds[index]
        previous_round = round_numbers[index - 1]
        current_round = round_numbers[index]
        require(current_round == previous_round + 1, "selected rounds are not contiguous")
        for role in ("reference", "candidate"):
            require(
                current[f"{role}_before"] == previous[f"{role}_after"],
                f"round {current_round}: {role} input state does not equal round {previous_round} output state",
            )
        previous_difference = state_difference(previous["reference_after"], previous["candidate_after"])
        current_difference = state_difference(current["reference_before"], current["candidate_before"])
        require(
            current_difference == previous_difference,
            f"round {current_round}: differential input state does not equal prior differential output state",
        )


def validate_genesis_bit0_window(
    analyzed_rounds: Sequence[dict[str, Any]],
    raw_rounds: Sequence[dict[str, Any]],
    round_numbers: Sequence[int],
) -> None:
    by_round = dict(zip(round_numbers, zip(analyzed_rounds, raw_rounds)))
    for round_number in round_numbers:
        if 4 <= round_number <= 18:
            analyzed, _ = by_round[round_number]
            expected_w_hamming = 1 if round_number == 4 else 0
            require(
                analyzed["message_w"]["xor_hamming"] == expected_w_hamming,
                f"round {round_number}: Genesis bit0 W hamming invariant failed",
            )
    if 4 in by_round:
        analyzed, raw = by_round[4]
        require(analyzed["input_state"]["total_hamming"] == 0, "round 4 input state hamming is not zero")
        require(analyzed["output_state"]["total_hamming"] > 0, "round 4 output state hamming is not positive")
        expected_values = {
            "reference_w": 0x1DAC2B7C,
            "candidate_w": 0x1CAC2B7C,
            "reference_temp1": 0x0A94A2A8,
            "candidate_temp1": 0x0994A2A8,
            "reference_new_a": 0x98610C20,
            "candidate_new_a": 0x97610C20,
            "reference_new_e": 0xC7253CDB,
            "candidate_new_e": 0xC6253CDB,
        }
        observed_values = {
            "reference_w": raw["reference_w"],
            "candidate_w": raw["candidate_w"],
            "reference_temp1": word(raw["reference_round"]["temp1"]["result"], "round4.reference.temp1"),
            "candidate_temp1": word(raw["candidate_round"]["temp1"]["result"], "round4.candidate.temp1"),
            "reference_new_a": raw["reference_after"]["a"],
            "candidate_new_a": raw["candidate_after"]["a"],
            "reference_new_e": raw["reference_after"]["e"],
            "candidate_new_e": raw["candidate_after"]["e"],
        }
        for name, expected_value in expected_values.items():
            require(
                observed_values[name] == expected_value,
                f"round 4 non-regression {name}={hex32(observed_values[name])}, expected {hex32(expected_value)}",
            )


def csv_text(rounds: Sequence[dict[str, Any]], sha: int, compression: int) -> str:
    fieldnames = [
        "sha",
        "compression",
        "round",
        "w_hamming",
        "input_state_hamming",
        "output_state_hamming",
        "sum0_hamming",
        "sum1_hamming",
        "choice_hamming",
        "majority_hamming",
        "temp1_hamming",
        "temp2_hamming",
        "new_a_hamming",
        "new_e_hamming",
        "choice_context_bits",
        "majority_context_bits",
        "temp1_context_bits",
        "temp2_context_bits",
        "new_a_context_bits",
        "new_e_context_bits",
        "round_context_certificate_sum",
        "temp1_carry_pair_diff_columns",
        "temp2_carry_pair_diff_columns",
        "new_a_carry_pair_diff_columns",
        "new_e_carry_pair_diff_columns",
        "temp1_max_abs_carry_diff",
        "temp2_max_abs_carry_diff",
        "new_a_max_abs_carry_diff",
        "new_e_max_abs_carry_diff",
        "temp1_modular_delta_signed32",
        "temp2_modular_delta_signed32",
        "new_a_modular_delta_signed32",
        "new_e_modular_delta_signed32",
    ]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for round_record in rounds:
        summary = round_record["round_summary"]
        additions = round_record["additions"]
        row: dict[str, Any] = {
            "sha": sha,
            "compression": compression,
            "round": summary["round"],
            "w_hamming": summary["w_hamming"],
            "input_state_hamming": summary["input_state_hamming"],
            "output_state_hamming": summary["output_state_hamming"],
            "sum0_hamming": summary["sum0_hamming"],
            "sum1_hamming": summary["sum1_hamming"],
            "choice_hamming": summary["choice_hamming"],
            "majority_hamming": summary["majority_hamming"],
            "temp1_hamming": summary["temp1_hamming"],
            "temp2_hamming": summary["temp2_hamming"],
            "new_a_hamming": summary["new_a_hamming"],
            "new_e_hamming": summary["new_e_hamming"],
            "choice_context_bits": summary["choice_context_certificate_bits"],
            "majority_context_bits": summary["majority_context_certificate_bits"],
            "temp1_context_bits": summary["temp1_context_certificate_bits"],
            "temp2_context_bits": summary["temp2_context_certificate_bits"],
            "new_a_context_bits": summary["new_a_context_certificate_bits"],
            "new_e_context_bits": summary["new_e_context_certificate_bits"],
            "round_context_certificate_sum": summary[
                "operation_local_context_certificate_bit_count_sum"
            ],
        }
        for addition_name in ("temp1", "temp2", "new_a", "new_e"):
            addition = additions[addition_name]
            row[f"{addition_name}_carry_pair_diff_columns"] = addition["summary"][
                "carry_pair_difference_column_count"
            ]
            row[f"{addition_name}_max_abs_carry_diff"] = addition["summary"][
                "max_absolute_carry_difference"
            ]
            row[f"{addition_name}_modular_delta_signed32"] = addition["modular_delta"][
                "signed32"
            ]
        writer.writerow(row)
    return stream.getvalue()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure exact operation-local context in recorded SHA-256 trajectories."
    )
    parser.add_argument("--trajectories", type=Path, default=Path("results/research_nonce_trajectories.json"))
    parser.add_argument("--diffusion", type=Path, default=Path("results/research_nonce_diffusion.json"))
    parser.add_argument("--reference-nonce", type=int, default=GENESIS_NONCE)
    parser.add_argument("--candidate-nonce", type=int, default=BIT0_CANDIDATE_NONCE)
    parser.add_argument("--sha", type=int, default=1)
    parser.add_argument("--compression", type=int, default=1)
    parser.add_argument("--round-start", type=int, default=4)
    parser.add_argument("--round-end", type=int, default=18)
    parser.add_argument("--output-prefix", type=Path, default=Path("results/research_causal_bit0"))
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
        "trajectories top-level reference_nonce does not match --reference-nonce",
    )
    require(
        diffusion_data.get("reference_nonce") == args.reference_nonce,
        "diffusion top-level reference_nonce does not match --reference-nonce",
    )

    reference = find_trajectory(trajectories_data, args.reference_nonce, "reference")
    candidate = find_trajectory(trajectories_data, args.candidate_nonce, "candidate")
    comparison = find_comparison(diffusion_data, args.candidate_nonce)
    require(reference is not candidate, "reference and candidate trajectories must differ")
    require(reference.get("final_hash") == GENESIS_HASH, "reference trajectory Genesis hash mismatch")
    require(diffusion_data.get("reference_hash") == GENESIS_HASH, "diffusion reference Genesis hash mismatch")
    require(
        comparison.get("final_hash") == candidate.get("final_hash"),
        "candidate final hash differs between trajectories and diffusion",
    )

    is_genesis_bit0_pair = (
        args.reference_nonce == GENESIS_NONCE and args.candidate_nonce == BIT0_CANDIDATE_NONCE
    )
    if is_genesis_bit0_pair:
        require(args.candidate_nonce - args.reference_nonce == -1, "bit0 candidate nonce delta is not -1")
        require(args.candidate_nonce == (args.reference_nonce ^ 1), "candidate is not numeric bit-0 flip")
        validate_bit0_labels(candidate, comparison)

    reference_compression = find_compression(reference, args.sha, args.compression, "reference")
    candidate_compression = find_compression(candidate, args.sha, args.compression, "candidate")
    round_numbers = list(range(args.round_start, args.round_end + 1))
    analyzed_rounds: list[dict[str, Any]] = []
    raw_rounds: list[dict[str, Any]] = []
    for round_number in round_numbers:
        analyzed, raw = analyze_round(
            round_number,
            args.sha,
            args.compression,
            reference_compression,
            candidate_compression,
            comparison,
        )
        analyzed_rounds.append(analyzed)
        raw_rounds.append(raw)
    validate_continuity(raw_rounds, round_numbers)

    is_genesis_bit0_compression = is_genesis_bit0_pair and args.sha == 1 and args.compression == 1
    if is_genesis_bit0_compression:
        validate_genesis_bit0_window(analyzed_rounds, raw_rounds, round_numbers)

    boolean_certificate_count = len(analyzed_rounds) * 2 * WORD_BITS
    addition_certificate_count = len(analyzed_rounds) * 4 * WORD_BITS
    report = {
        "schema_version": 1,
        "analysis": "exact_local_causal_differential_context",
        "metadata": {
            "experiment_purpose": (
                "Study exact differential propagation after a one-bit nonce perturbation "
                "during the window between direct W3 injection and the first extended-schedule reinjection."
            ),
            "trajectories_source": str(args.trajectories),
            "diffusion_cross_check_source": str(args.diffusion),
            "primary_value_source": "trajectories",
            "reference_nonce": args.reference_nonce,
            "candidate_nonce": args.candidate_nonce,
            "reference_hash": reference.get("final_hash"),
            "candidate_hash": candidate.get("final_hash"),
            "sha": args.sha,
            "compression": args.compression,
            "round_start": args.round_start,
            "round_end": args.round_end,
            "round_numbering": "human_1_to_64",
            "bit_numbering": "numeric_lsb_is_bit_0",
            "difference_direction": "candidate_minus_reference",
            "certificate_subset_order": "increasing_cardinality_then_lexicographic_operand_order",
            "addition_carry_pair_difference_definition": (
                "reference_carry_out_value differs from candidate_carry_out_value"
            ),
        },
        "limitations": {
            "global_minimum_raw_state_context_not_computed": True,
            "local_certificates_are_operation_specific": True,
            "derived_values_can_cause_double_counting": True,
        },
        "validation": {
            "reference_genesis_hash": True,
            "trajectories_used_as_primary_values": True,
            "diffusion_cross_check": True,
            "exact_carry_columns": True,
            "recorded_nonzero_carry_masks_cross_checked": True,
            "linear_xor_identities": True,
            "round_state_continuity": True,
            "genesis_bit0_labels": True if is_genesis_bit0_pair else "not_applicable",
            "genesis_bit0_window_invariants": (
                True if is_genesis_bit0_compression else "not_applicable"
            ),
            "default_experiment": (
                True
                if is_genesis_bit0_compression
                and args.round_start == 4
                and args.round_end == 18
                else "not_applicable"
            ),
        },
        "rounds": analyzed_rounds,
        "summary": {
            "round_count": len(analyzed_rounds),
            "rounds": round_numbers,
            "addition_count": len(analyzed_rounds) * 4,
            "addition_column_count": addition_certificate_count,
            "boolean_local_certificate_count": boolean_certificate_count,
            "addition_local_certificate_count": addition_certificate_count,
            "diffusion_cross_check": "passed",
            "exact_carry_column_analysis": "passed",
        },
    }
    return report, csv_text(analyzed_rounds, args.sha, args.compression)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output_json = Path(f"{args.output_prefix}.json")
    output_csv = Path(f"{args.output_prefix}.csv")
    input_paths = {args.trajectories.resolve(), args.diffusion.resolve()}
    require(output_json.resolve() not in input_paths, "JSON output would overwrite an input file")
    require(output_csv.resolve() not in input_paths, "CSV output would overwrite an input file")
    require(output_json != output_csv, "JSON and CSV output paths collide")

    report, csv_report = build_report(args)
    json_report = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json_report, encoding="utf-8")
    output_csv.write_text(csv_report, encoding="utf-8", newline="")

    print(f"[CAUSAL] reference={args.reference_nonce} candidate={args.candidate_nonce}")
    print(
        f"[CAUSAL] SHA{args.sha} compression={args.compression} "
        f"rounds={args.round_start}..{args.round_end}"
    )
    print(f"[CAUSAL] {report['summary']['round_count']} rounds validated")
    print("[CAUSAL] diffusion cross-check OK")
    print("[CAUSAL] exact carry columns OK")
    print(f"[CAUSAL] reports saved: {output_json}, {output_csv}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AnalysisError, OSError) as exc:
        print(f"[CAUSAL] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
