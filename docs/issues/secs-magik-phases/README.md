# secS-magik phase issue specs

This directory contains repo-local, issue-ready phase specs for secS-magik ready-for-production tracks. Phase GitHub issues are the tracking containers; tasks inside each phase issue are intended commit boundaries.

## Active / recent specs

| Track | GitHub issue | Local spec | Status |
|---|---:|---|---|
| Track E — trusted issuer/root policy | #63 / underlying #35 | [`track-e-trusted-issuer-root-policy.md`](track-e-trusted-issuer-root-policy.md) | complete; PR #69 merged to `main` at `baee35b`, post-merge CI run 27050361282 passed |
| Track I — production-shaped `membership.provision` E2E | #70 | [`track-i-production-membership-provision-e2e.md`](track-i-production-membership-provision-e2e.md) | complete for local production-shaped E2E; PR #76 merged to `main` at `5e5bb71`, post-merge CI run 27071532041 passed |

## Proposed demoable milestone (M12)

These are repo-local specs (2026-06-09) for reaching a demoable
end-to-end state — authenticated caller, signed decision returned to the caller,
and a boundary-preserving Castalia-over-Dregg-shaped evidence seam — plus the
correctness/supply-chain hardening a credible demo needs. Filed as GitHub issues
2026-06-09: umbrella #88, children #89-#95 (linked in the table below). They are complementary to (not duplicates of) the
`membership.provision` live-ingress hardening tracked in #78–#83, and they must
not be used to close the future authority rails #71–#75.

| Spec | GitHub issue | Local file | Demo role |
|---|---:|---|---|
| M12 (umbrella) | #88 | [`m12-demoable-milestone.md`](m12-demoable-milestone.md) | Sequences M12.1–M12.7 and records the demo boundary |
| M12.1 | #89 | [`m12-1-caller-proof-authentication.md`](m12-1-caller-proof-authentication.md) | Verify caller proof-of-origin signature on ingress |
| M12.2 | #90 | [`m12-2-caller-decision-response.md`](m12-2-caller-decision-response.md) | Return a signed accept/reject decision to the caller |
| M12.3 | #91 | [`m12-3-dregg-shaped-evidence-adapter.md`](m12-3-dregg-shaped-evidence-adapter.md) | Dregg-shaped evidence adapter seam (shape + signature only; not #73 authority) |
| M12.4 | #92 | [`m12-4-tunnel-aead-aad-binding.md`](m12-4-tunnel-aead-aad-binding.md) | Bind tunnel AEAD to session_id + opcode |
| M12.5 | #93 | [`m12-5-failclosed-clock-reads.md`](m12-5-failclosed-clock-reads.md) | Fail-closed clock reads on the verification path |
| M12.6 | #94 | [`m12-6-retire-decorative-mac.md`](m12-6-retire-decorative-mac.md) | Verify, reserve, or remove the decorative `mac` field |
| M12.7 | #95 | [`m12-7-supply-chain-ci-gate.md`](m12-7-supply-chain-ci-gate.md) | Supply-chain audit CI gate + dependency bump |

## Gap / future-rail issues after Track E

| Gap / forbidden claim | GitHub issue | Status |
|---|---:|---|
| Production-shaped `membership.provision` E2E | #70 | closed by PR #76 at `5e5bb71` with post-merge CI 27071532041; post-merge review follow-ups are #77-#84 |
| Full Castalia Wallet wallet-core parity | #71 | open |
| Live Castalia trusted issuer registry discovery | #72 | open |
| Dregg capability/proof/revocation authority | #73 | open |
| Midnight proof verification | #74 | open |
| Cardano settlement/finality evidence | #75 | open |
| Production deployment proof | #33 | open |
| Public auditability beyond local SQLite receipts | #37 | open |

## Boundary

These specs are planning/control artifacts. Implementation still happens on a focused phase branch and must update `README.md`, `server/README.md`, `docs/implementation-status.md`, `docs/repository-schema.md`, `docs/plans/2026-06-02-ready-for-prod-checklist.md`, `CHANGELOG.md`, the vault master checklist, and the relevant GitHub issues/PR body when a phase lands.
