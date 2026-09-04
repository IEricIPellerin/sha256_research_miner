#!/usr/bin/env python3
"""Independent hashlib audit for the 64 x 32 white-box transfer artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path


SEED = b"SRM_WHITEBOX_MERKLE_CONTEXT_V1"


def digests(header: bytes) -> tuple[str, str, str]:
    first = hashlib.sha256(header).digest()
    raw = hashlib.sha256(first).digest()
    return first.hex(), raw.hex(), raw[::-1].hex()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "artifact_directory",
        nargs="?",
        default="results/whitebox/merkle_context_transfer_64",
        type=Path,
    )
    args = parser.parse_args()
    directory = args.artifact_directory
    contexts_path = directory / "merkle_context_transfer_64_contexts.csv"
    bits_path = directory / "merkle_context_transfer_64_per_context_bit.csv"
    aggregate_path = directory / "merkle_context_transfer_64_aggregate.json"
    summary_path = directory / "merkle_context_transfer_64_summary.md"

    with contexts_path.open(newline="", encoding="utf-8") as stream:
        contexts = list(csv.DictReader(stream))
    require(len(contexts) == 64, f"expected 64 contexts, got {len(contexts)}")

    prefixes: dict[int, bytes] = {}
    reference_checked = 0
    for expected_id, row in enumerate(contexts):
        context_id = int(row["context_id"])
        require(context_id == expected_id, "context ids are not ordered 0..63")
        require(
            row["split"] == ("discovery" if context_id < 32 else "holdout"),
            f"split mismatch for context {context_id}",
        )
        merkle = hashlib.sha256(SEED + struct.pack("<I", context_id)).digest()
        require(
            merkle.hex() == row["merkle_header_bytes_hex"],
            f"Merkle fixture mismatch for context {context_id}",
        )
        require(
            merkle[::-1].hex() == row["merkle_display_hex"],
            f"Merkle display mismatch for context {context_id}",
        )
        prefix = bytes.fromhex(row["header_prefix_76_hex"])
        require(len(prefix) == 76, f"prefix length mismatch for context {context_id}")
        require(prefix[36:68] == merkle, f"Merkle insertion mismatch for context {context_id}")
        header = prefix + struct.pack("<I", 2083236893)
        first, raw, display = digests(header)
        require(first == row["first_sha256"], f"reference first SHA mismatch {context_id}")
        require(raw == row["raw_sha256d"], f"reference SHA256d mismatch {context_id}")
        require(display == row["bitcoin_display_hash"], f"reference display mismatch {context_id}")
        prefixes[context_id] = prefix
        reference_checked += 1

    with bits_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == 2048, f"expected 2048 candidates, got {len(rows)}")
    candidate_checked = 0
    for expected_sequence, row in enumerate(rows):
        context_id = int(row["context_id"])
        bit = int(row["numeric_nonce_bit"])
        require(
            expected_sequence == context_id * 32 + bit,
            "candidate rows are not ordered context-major then bit-major",
        )
        expected_split = "discovery" if context_id < 32 else "holdout"
        require(row["split"] == expected_split, "candidate split mismatch")
        nonce = 2083236893 ^ (1 << bit)
        require(int(row["nonce_candidate"]) == nonce, "candidate nonce mismatch")
        header = prefixes[context_id] + struct.pack("<I", nonce)
        first, raw, display = digests(header)
        require(first == row["first_sha256"], f"candidate first SHA mismatch {context_id}/{bit}")
        require(raw == row["raw_sha256d"], f"candidate SHA256d mismatch {context_id}/{bit}")
        require(display == row["bitcoin_display_hash"], f"candidate display mismatch {context_id}/{bit}")
        candidate_checked += 1

    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    validations = aggregate["validations"]
    validations["independent_python_reference_vectors_checked"] = reference_checked
    validations["independent_python_candidate_vectors_checked"] = candidate_checked
    validations["independent_python_mismatches"] = 0
    validations["independent_python_audit_status"] = "passed"
    aggregate["audit"]["independent_python_reference_vectors_checked"] = reference_checked
    aggregate["audit"]["independent_python_candidate_vectors_checked"] = candidate_checked
    aggregate["audit"]["independent_python_mismatches"] = 0
    aggregate["audit"]["independent_python_audit_status"] = "passed"
    aggregate_path.write_text(
        json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    summary = summary_path.read_text(encoding="utf-8")
    summary = summary.replace(
        "Audit Python indépendant: PENDING_EXTERNAL_DEVELOPMENT_AUDIT.",
        "Audit Python indépendant: 64/64 références et 2048/2048 candidats; 0 mismatch.",
    )
    summary_path.write_text(summary, encoding="utf-8")
    print(
        f"independent_python_reference_vectors_checked={reference_checked}\n"
        f"independent_python_candidate_vectors_checked={candidate_checked}\n"
        "mismatches=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
