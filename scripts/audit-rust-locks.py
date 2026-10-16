#!/usr/bin/env python3
"""Audit every tracked Rust lockfile, including standalone native/tool workspaces."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
locks = sorted(name for name in tracked if name and Path(name).name == "Cargo.lock")
if not locks:
    raise SystemExit("No tracked Cargo.lock files found; audit coverage is missing.")
failed = False
for name in locks:
    print(f"Auditing {name}", flush=True)
    result = subprocess.run(["cargo", "audit", "--file", name, *sys.argv[1:]], cwd=root, env=os.environ)
    failed |= result.returncode != 0
raise SystemExit(int(failed))
