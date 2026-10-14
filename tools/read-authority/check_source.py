"""Verify the retained source snapshot without accessing private Wallet source.

Devgraph's matched companion lane separately compares these bytes with Wallet
at SOURCE.json's exact revision. This check is not installed qualification.
"""

import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
source = json.loads((root / "SOURCE.json").read_text())
expected_files = {"Cargo.toml", "LICENSE", "src/lib.rs", "src/read_authority.rs",
                  "tests/read_authority.rs"}
if set(source["files"]) != expected_files:
    raise SystemExit("Read-authority snapshot file inventory changed; review provenance.")
for name, expected in source["files"].items():
    actual = hashlib.sha256((root / "vendor/castalia-wallet-presentation" / name).read_bytes())
    if actual.hexdigest() != expected:
        raise SystemExit(f"Read-authority snapshot checksum mismatch: {name}")
print("All five retained Wallet source hashes match SOURCE.json.")
