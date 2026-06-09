# Phase M12 — demoable end-to-end secS milestone (authenticated, answerable, inspectable)

> Status: proposed (2026-06-09). Filed as a repo-local spec because the current
> automation integration is read-only on GitHub issue creation. Promote to a
> GitHub issue and link the child issues when write access is available.

## Objective

Bring secS-magik from "well-tested verifier substrate with an inert/unauthenticated
live path" to a **demoable end-to-end state**: a viewer can watch a client make a
call, see secS authenticate the caller, verify wallet + Castalia/Dregg-shaped
evidence, enforce replay/expiry/session bindings, return a signed accept/reject
decision to the caller, and let an operator inspect the resulting receipt chain.

This is a tracking/umbrella spec. It does not itself change code; it sequences the
child specs (M12.1–M12.7) and records the demo boundary so no child overclaims.

## Why this is needed (current read after #84)

The repo is in good engineering health (clean build, full test suite passing,
clippy `-D warnings` in CI, fail-closed production config). But the live network
path cannot be demonstrated as a *verifier*:

- **No caller authentication.** `Verifier::verify_prototype_envelope`
  (`server/src/verifier.rs`) accepts any packet whose `proof` is non-empty and
  `claim_ttl > 0`. The client's Ed25519 signature over the payload
  (`client/src/main.rs`) is never checked server-side, and there is no caller key
  seam. In dev modes anyone who can reach the port can drive the dev handlers.
- **No answer to the caller.** The client writes a packet and never reads a
  response (`dispatch_packet` in `client/src/main.rs`); the gateway never sends
  one. A demo cannot show the verifier's decision to the party that made the call.
- **No Dregg-shaped evidence seam.** `EvidenceKind` already declares
  `DreggReceipt`, `MidnightProof`, `CardanoSettlement` (`server/src/evidence.rs`)
  but there is no adapter for any of them, so secS cannot demonstrate ingesting
  Castalia-over-Dregg-shaped evidence at all.
- **Correctness/hygiene gaps** that would undermine a credible demo: tunnel AEAD
  has no associated-data binding to `session_id`/`opcode` (ciphertext splicing
  bypasses the replay key); clock-read failure fails *open* on the hot path; the
  `mac` field is filled with random bytes and never checked; CI has no
  supply-chain gate and `sqlx` is pinned to a version with a known advisory.

`membership.provision` live-ingress/handler/manifest hardening is already tracked
by #78–#83 and is complementary to this milestone — M12 supplies the
caller-authentication, caller-response, and Dregg-shaped-evidence seams that those
issues assume.

## Demo boundary (must hold for every child)

Per the secS boundary notes and `emberian/dregg`:

- secS is the **generic verifier/gateway seam**, not the product noun, not
  Castalia/Gallery membership authority, not Dregg consensus.
- secS **verifies** wallet presentations, challenge/replay/session bindings,
  credential-chain inputs, and **Dregg-shaped roots/receipts/revocation/capability
  evidence**, then hands verified material to the local Hub/secZ policy layer. It
  does not apply product policy.
- The Dregg-shaped evidence seam in this milestone is **shape + author-signature
  verification only** (mirroring how Track D landed the wallet challenge as a
  temporary minimal-equivalent contract). It is explicitly **not** Dregg blocklace
  finality, capability non-amplification, nullifier/no-double-spend, CapTP
  handoff, or revocation authority — those remain #73.
- Caller proof-of-origin authentication is **necessary but never sufficient**
  authority: it proves who sent the packet, not membership/issuer/root authority.

## Child specs (dependency-aware order)

| ID | Spec | Demo role |
|---|---|---|
| M12.1 | [`m12-1-caller-proof-authentication.md`](m12-1-caller-proof-authentication.md) | Verify caller proof-of-origin signature on ingress |
| M12.2 | [`m12-2-caller-decision-response.md`](m12-2-caller-decision-response.md) | Return a signed accept/reject decision to the caller |
| M12.3 | [`m12-3-dregg-shaped-evidence-adapter.md`](m12-3-dregg-shaped-evidence-adapter.md) | Boundary-preserving Dregg-shaped evidence adapter seam |
| M12.4 | [`m12-4-tunnel-aead-aad-binding.md`](m12-4-tunnel-aead-aad-binding.md) | Bind tunnel AEAD to session_id + opcode |
| M12.5 | [`m12-5-failclosed-clock-reads.md`](m12-5-failclosed-clock-reads.md) | Fail-closed clock reads on the verification path |
| M12.6 | [`m12-6-retire-decorative-mac.md`](m12-6-retire-decorative-mac.md) | Verify, reserve, or remove the `mac` field |
| M12.7 | [`m12-7-supply-chain-ci-gate.md`](m12-7-supply-chain-ci-gate.md) | Supply-chain audit CI gate + dependency bump |

Suggested sequencing: M12.1 → M12.2 unlock the visible request/response demo;
M12.3 adds the Castalia-over-Dregg evidence story; M12.4–M12.6 are correctness
hardening that should land before the demo is shown; M12.7 is independent and can
land any time.

## Acceptance for M12 (milestone closes only when)

- A scripted demo (extend `examples/`) shows, against the real gateway:
  authenticated caller accept; unauthenticated/forged-proof reject; wallet +
  Dregg-shaped evidence accept; replay/expiry reject; caller receiving the signed
  decision; operator inspecting the verify+execute (or verify+reject) receipt
  chain.
- Every child spec merged with post-merge main CI green.
- `README.md` / `docs/implementation-status.md` / `CHANGELOG.md` describe the
  demoable state without crossing any forbidden-claim boundary below.

## Forbidden claims (carry into every child)

Do not claim, on the basis of this milestone: production deployment proof (#33);
public auditability beyond local SQLite (#37); full Castalia wallet-core parity
(#71); live Castalia registry discovery (#72); **Dregg
capability/proof/revocation/finality authority (#73)** — the Dregg seam here is
shape+signature only; Midnight (#74) or Cardano (#75) authority; or that caller
proof-of-origin is membership/issuer/root authority.

## References

- Security/readiness review of `main` (2026-06-09 session).
- secS boundary notes; `emberian/dregg` (Lean 4 + Rust; blocklace DAG,
  Ed25519-authenticated inserts, capabilities-as-witnesses, strands, receipts,
  revocation, finality).
- Complementary live-ingress hardening: #78, #79, #80, #81, #82, #83.
- Future authority rails (out of scope here): #33, #37, #71, #72, #73, #74, #75.
