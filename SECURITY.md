# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub Security Advisories
(`Security` tab → `Report a vulnerability`) on `ZenithResearch/secS-magik`.
Do not open public issues for unpatched vulnerabilities.

## Supply-chain posture

- CI runs `cargo audit` on every PR and push to `main` and **fails on any
  known RUSTSEC vulnerability** in `Cargo.lock`.
- There is no blanket ignore list. If an advisory ever needs to be waived
  (e.g. a transitive advisory with no fixed release), it must be added to
  `audit.toml` with a written justification and a tracking issue.
- Dependabot watches Cargo and GitHub Actions dependencies weekly
  (`.github/dependabot.yml`).

## Known accepted warnings (not vulnerabilities)

| Advisory | Crate | Status | Justification |
|---|---|---|---|
| RUSTSEC-2025-0141 | `bincode 1` | unmaintained warning | The v0 packet wire format is deliberately frozen on bincode 1; migrating the wire format is an explicitly owned future change, not a drive-by bump (see repo packet-shape rule). |
| RUSTSEC-2024-0436 | `paste` | unmaintained warning | Transitive via `uniffi`; goes away when upstream uniffi drops it. |

## Boundary note

A clean advisory scan is a dependency-hygiene gate only. It is not
production deployment proof (#33) and not a full security audit.
