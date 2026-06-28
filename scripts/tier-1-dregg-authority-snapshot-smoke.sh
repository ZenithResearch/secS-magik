#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT/fixtures/dregg/david-lab-authority-snapshot.json"

cd "$ROOT"

cat <<'EOF'
secS Tier 1 Dregg authority snapshot smoke (#72/#195)

Boundary:
- local fixture-backed Dregg-shaped authority snapshot consumption;
- arbitrary entity/resource authority: did:example:david-lab -> resource://david-lab/*;
- fail-closed receiver-local enforcement;
- not live Castalia Dregg API, full Dregg node, finality, production deployment, or public auditability.
EOF

python3 - "$FIXTURE" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
snapshot = json.loads(text)
forbidden_key = re.compile(r"(private|secret|token|password|seed)", re.IGNORECASE)
forbidden_value = re.compile(r"(-----BEGIN|sk_|ghp_|gho_|xoxb-|PRIVATE KEY)")

def walk(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if forbidden_key.search(key):
                raise SystemExit(f"redaction_fail: forbidden fixture key at {path}.{key}")
            walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(child, f"{path}[{index}]")
    elif isinstance(value, str) and forbidden_value.search(value):
        raise SystemExit(f"redaction_fail: forbidden fixture value at {path}")

walk(snapshot)
print(f"fixture_ok: {snapshot['schema_version']} {snapshot['entity_id']} {snapshot['namespace_id']}")
for resource in snapshot["resources"]:
    print(f"resource_ok: {resource['resource_id']} controller={resource['controller_entity_id']} status={resource['status']}")
print("redaction_ok: fixture contains no raw secret/private-token markers")
PY

cargo test -p server --test dregg_authority_registry dregg_authority_snapshot -- --nocapture

cat <<'EOF'
smoke_ok: active snapshot accepts the controlled David Lab resource; stale, revoked, wrong namespace, wrong resource, missing source, and unknown issuer reject.
EOF
