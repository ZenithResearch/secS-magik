#!/usr/bin/env python3
"""Write deterministic SHA-256 inventory for the browser intake package."""

from __future__ import annotations

import hashlib
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: hash-browser-intake-sealer.py OUTPUT_DIRECTORY")
    root = pathlib.Path(sys.argv[1])
    names = [
        "README.md",
        "index.d.ts",
        "index.js",
        "libsec_core.d.ts",
        "libsec_core.js",
        "libsec_core_bg.wasm",
        "package.json",
    ]
    if not root.is_dir() or any(not (root / name).is_file() for name in names):
        raise SystemExit("browser intake package is incomplete")
    lines = [f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}"
             for name in names]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

