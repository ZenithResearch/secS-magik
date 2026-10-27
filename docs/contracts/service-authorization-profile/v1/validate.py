"""Validate proposed documentation fixtures; not a runtime authority evaluator.

Run: uv run --no-project --with jsonschema==4.23.0 python validate.py
"""

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "descriptor.schema.json").read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
# Fixture support registry, not a claim that runtime adapters are installed.
SUPPORTED_CONSTRAINT_PROFILES = frozenset({
    "constraints.exact.v1", "devgraph.arena.constraints.v1", "devgraph.work.constraints.v1",
})


def validate(value):
    VALIDATOR.validate(value)
    groups = [value[name] for name in ("resources", "operations", "presets")]
    for group in groups:
        if len({row["id"] for row in group}) != len(group):
            raise ValueError("duplicate identifier")
    if any(row["constraints_profile"] not in SUPPORTED_CONSTRAINT_PROFILES for row in value["operations"]):
        raise ValueError("unsupported constraint profile")
    resources = {row["id"] for row in value["resources"]}
    operations = {row["id"] for row in value["operations"]}
    if any(row["resource"] not in resources for row in value["operations"]):
        raise ValueError("unknown operation resource")
    if any(not set(row["operations"]) <= operations for row in value["presets"]):
        raise ValueError("unknown recipe operation")


def rejected(value):
    try:
        validate(value)
    except (ValueError, ValidationError):
        return
    raise AssertionError("invalid fixture accepted")


if __name__ == "__main__":
    profiles = [json.loads((ROOT / name).read_text()) for name in (
        "devgraph.example.json", "album-service.example.json", "media-library.example.json")]
    for profile in profiles:
        validate(profile)
        bad = copy.deepcopy(profile); bad["onward_delegation"] = True; rejected(bad)
        bad = copy.deepcopy(profile); bad["operations"][0]["constraints_profile"] = "unsupported.profile.v1"; rejected(bad)
        bad = copy.deepcopy(profile); bad["endpoint"] = "https://example.invalid"; rejected(bad)
        bad = copy.deepcopy(profile); bad["resources"][0]["selector"] = "execute-script"; rejected(bad)
        bad = copy.deepcopy(profile); bad["operations"][0]["resource"] = "unknown"; rejected(bad)
        bad = copy.deepcopy(profile); bad["presets"][0]["operations"] = ["unknown"]; rejected(bad)
        bad = copy.deepcopy(profile); duplicate = copy.deepcopy(bad["operations"][0]); duplicate["label"] = "Different label"; bad["operations"].append(duplicate); rejected(bad)
    print(json.dumps({"profiles_validated": len(profiles), "negative_cases_rejected": 21,
                      "runtime_authorization_tested": False}))
