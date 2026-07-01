#!/usr/bin/env python3
"""Static contract check for the M15.8 web demo.

This intentionally checks semantic UI/demo requirements rather than pixel layout:
- runnable browser files exist;
- success and failure paths are explicitly guided;
- production-shaped vs not-proven boundaries are visible;
- README tells an operator how to serve the demo.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "examples/m15-dregg-authority-demo/web/index.html"
JS = ROOT / "examples/m15-dregg-authority-demo/web/demo.js"
README = ROOT / "examples/m15-dregg-authority-demo/README.md"

html = HTML.read_text() if HTML.exists() else ""
js = JS.read_text() if JS.exists() else ""
readme = README.read_text() if README.exists() else ""

checks = {
    "web demo html exists": HTML.exists(),
    "web demo js exists": JS.exists(),
    "success case button": 'id="run-success-case"' in html,
    "resource lock failure button": 'id="run-resource-lock-failure"' in html,
    "missing evidence failure button": 'id="run-missing-evidence-failure"' in html,
    "guided walkthrough steps": "Demo walkthrough" in html and "Step 1" in html and "Step 2" in html,
    "clear production boundary": "What is production-shaped" in html and "What is not proven" in html,
    "no live network overclaim": "no live Castalia/Dregg network call" in html,
    "success decision modeled": "resource_lock:verified" in js and "VERIFY ACCEPTED" in js and "EXECUTE ACCEPTED" in js,
    "resource-lock failure modeled": "resource_lock_violation" in js and "VERIFY REJECTED" in js,
    "missing-evidence failure modeled": "missing_dregg_authority_evidence" in js,
    "readme has web instructions": "Web demo" in readme and "python3 -m http.server" in readme,
}

for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)

if not all(checks.values()):
    raise SystemExit(1)
