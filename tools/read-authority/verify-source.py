#!/usr/bin/env python3
"""Verify the frozen source; optionally compare a coordinated Wallet checkout."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
manifest = json.loads((root / "SOURCE.json").read_text())
for name, expected in manifest["files"].items():
    frozen = root / "vendor/castalia-wallet-presentation" / name
    assert hashlib.sha256(frozen.read_bytes()).hexdigest() == expected, name
    if len(sys.argv) == 2:
        current = Path(sys.argv[1]) / "crates/castalia-wallet-presentation" / name
        assert current.read_bytes() == frozen.read_bytes(), name
print("Shared read authority source hashes and requested parity checks passed.")
