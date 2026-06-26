# Dregg authority rail

Status: M15.1 / #137 specification. This rewrites #73 acceptance criteria, but #137 is docs/spec only and does not close the parent issue.

## Purpose

This spec defines the M15 `dregg_authority` semantics gate. It separates M12.3 Dregg-shaped evidence, M14 `dregg_backed`, and the bounded M15 production-shaped authority seam while preserving the original receiver-held root/trust data, epoch-scoped root policy, and freshness/revocation/finality/non-amplification posture. M15.2–M15.6 now implement static receiver-held registry, policy-admission, descriptor-composition, and local-operator disclosure; #159 has resolved proof/finality as explicit fail-closed blocker posture and #162 wires live TCP evidence propagation into the canonical evidence adapter path; Dregg resource locks and finalizer closure remain #160 and #144/M15.8 work.

## Tier boundary

The production rail has three distinct tiers that must not be collapsed:

1. M12.3 shape-only: `dregg_receipt` / `secs-dregg-receipt-shape-v1` means shape + author signature only. It validates envelope shape and author signature material, not Dregg semantic authority.
2. M14 `dregg_backed`: a `dga1_...` grant token can be admitted by `dregg-auth::policy::Verifier::admit` against a configured issuer public key. This is subject + tool + clock only. The Dregg policy layer does not verify secS resource authority; receiver-local resource scope remains enforced by secS.
3. M15 `dregg_authority`: a production authority bundle is admitted only against receiver-held production trust policy, epoch-scoped federation/root policy, and explicit revocation/freshness posture. It may later compose with proof/finality material, but that claim must be tied to the rotated-replay IR-v2 chain and not to a single legacy proof helper.

A successful Dregg admission is necessary but not sufficient for any handler side effect. Receiver-local manifest policy, descriptor-local policy, permission policy, replay/session/TTL checks, and bounded handler execution still apply before side effects.

## Authority object taxonomy

No production issue after M15.1 may use “Dregg proof” or “Dregg authority” vaguely. The authority object taxonomy is:

| Object | Definition | Production boundary |
|---|---|---|
| token | The presented `dga1_...` grant token. | Parsed/admitted by Dregg policy; not sufficient by itself. |
| issuer | Dregg issuer id / issuer key / issuer fingerprint. | Must be present in receiver-held production trust policy. |
| federation root | Root or federation authority fingerprint used for Dregg production policy. | Must be receiver-held and, when federation semantics are claimed, epoch-scoped. |
| epoch | Root/federation validity epoch. | Wrong or stale epoch rejects as `wrong_epoch` or `stale`. |
| revocation/status | Revocation root, token status, issuer status, root status, and status timestamp. | Required when production policy says revoked or stale authority must fail closed. |
| freshness | Validation time, status age, and authoritative clock/status source. | Defines stale authority and max accepted status age. |
| proof/finality | Optional finality/equivocation proof bundle. | Not a production claim until a verifier path is selected and tested. |
| public inputs | Subject, audience, opcode, operation, resource, validity, nonce/replay, root, epoch, and status. | Every input must bind to the descriptor/request context. |

## Accepted statements and public inputs

A future production `dregg_authority` adapter must define which Dregg API verifies each public input and which secS layer enforces what Dregg does not. Minimum accepted statements:

- subject: the token subject must match the authenticated caller / verified subject expected by secS.
- audience: the receiver audience must match the configured secS receiver.
- opcode: the secS `u8` opcode must match the receiver-local descriptor being verified.
- operation: the secS operation maps deterministically to the Dregg policy `tool` admitted by `dregg-auth::policy::Verifier::admit`.
- resource: resource canonicalization is receiver-local in M14; in M15, resource is either receiver-local policy or an explicit lower-level Dregg credential caveat design choice. `Call.args.resource` is advisory, not a trusted authorization gate.
- validity: Dregg token validity and secS descriptor/context TTL are both enforced; neither silently extends the other.
- nonce/replay: secS replay/session/nonce remains active. Any Dregg replay/nullifier/finality semantics must be named separately.
- root: trusted root/federation root must be receiver-held, not caller-supplied.
- epoch: federation/root authority is epoch-scoped when federation authority is claimed.
- status: revocation/status/freshness material must bind to issuer, token, root, and validation time.



## M15 proof hardening / #159 proof/finality blocker posture

#159 adds explicit tested posture for the Dregg proof/finality blockers named by #140 before #144 can finalize #73. secS now binds a receiver-held `expected_revocation_root` through an attested fixture/root reference and fails closed with `missing_revocation_root` or `wrong_revocation_root`; caller-supplied public inputs cannot satisfy that root binding.

The upstream live verifier surfaces remain named blockers because this repository does not yet import or wire Dregg federation proof APIs: `credentials::VerificationOptions.expected_revocation_root`, federation `RevocationVerifier` / `RevocationTree`, `ReceiptQc::Threshold` with BLS FederationCommittee plumbing, and `rotated_replay::verify_rotated_replay_chain`. If a registry policy requires those live surfaces, the current adapter rejects with `unsupported_revocation_verifier`, `unsupported_bls_threshold_finality`, or `unsupported_rotated_replay_verifier` rather than accepting fixture status as proof.

This is no live Dregg revocation proof, no BLS threshold finality, and no rotated-replay proof verification. #162 live ingress evidence refs do not change that blocker posture; #144/M15.8 closes only the bounded #73 production-shaped seam by explicitly documenting those live verifier paths as finalizer non-goals for this repository; live Dregg revocation proof, BLS threshold finality, and rotated-replay proof verification remain unsupported.

## Composition rules

Dregg is not a bypass. A descriptor may require `dregg_authority`, but that never replaces other required evidence layers:

- wallet proof-of-possession remains necessary where required but never sufficient for issuer/root or Dregg authority.
- wallet PoP proves possession of the claimed subject key only.
- trusted-issuer credential evidence remains governed by trusted issuer/root policy.
- receiver-local manifest policy and descriptor-local policy decide whether the evidence kind is even accepted for the opcode/operation/resource.
- receiver-local permission policy remains default-deny and deny-wins.
- Dregg authority cannot make a dev/prototype descriptor production-authorized.
- Dregg authority cannot authorize local side effects that the receiver-local resource/effect policy denies.

## Failure-reason taxonomy

M15.2+ should map Dregg failures into stable typed reasons. Minimum names for docs/tests:

- `wrong_root`: receiver-held root/federation root mismatch.
- `wrong_epoch`: presented root/federation epoch is not valid for the receiver policy.
- `stale`: freshness/status age exceeds receiver policy.
- `revoked`: token, issuer, credential, status, or root is revoked.
- `not_final`: proof/finality material is required but not final enough.
- `equivocated`: proof/finality material indicates equivocation.
- `malformed`: token or authority bundle cannot be parsed.
- `unsupported_suite`: token/proof/signature/version suite is unsupported.
- `wrong_binding`: generic binding mismatch.
- wrong subject: subject does not match the call context.
- wrong audience: receiver/audience mismatch.
- wrong operation: Dregg tool / secS operation mismatch.
- wrong resource: resource canonicalization or policy mismatch.
- missing status: required revocation/status material is absent.
- invalid admission: `dregg-auth::policy::Verifier::admit` denies the token.

## Revocation/status and freshness decision

M15.1 does not implement code, but it chooses the production bundle shape that later issues must satisfy:

- The minimum production bundle is not just `dga1_...` plus any caller-provided root. It is `dga1_...` plus receiver-held production trust policy and the revocation/status/freshness material required by that policy.
- The receiver holds the trusted issuer/root entries and, where federation authority is claimed, an epoch-scoped federation/root entry.
- Freshness means the token/status/root decision is evaluated at a receiver-known validation time and within the max age allowed by policy.
- Revocation means issuer/root/token/status material can be rejected according to the Dregg revocation API selected by M15.2/M15.4.
- If Dregg upstream cannot provide a selected revocation/status verifier for the required production claim, the adapter must fail closed or mark production Dregg authority not ready.

Candidate API surfaces for later implementation are Dregg low-level credential `VerificationOptions.expected_revocation_root`, Dregg federation `RevocationVerifier`, or an explicit composition of both. M15.2/M15.4 must choose and test the concrete path.

## Proof/finality posture

`verify_effect_vm_proof` is not the whole live path. Under Dregg recursion, the current deep verifier posture is the rotated-replay IR-v2 chain: `dregg_verifier::rotated_replay::verify_rotated_replay_chain`, with `verify_rotated_leg`, `RotatedReplayLeg`, and `RotatedReplayVerdict` as related surfaces.

For #73, proof/finality is a named production question, not an implicit current claim. Until a later issue explicitly wires and tests rotated-replay/finality/equivocation material, `dregg_authority` may claim token/root/status admission only, not blocklace finality, public proof verification, public auditability, or settlement finality.



## M15.4 / #140 revocation/freshness/finality posture

M15.4 (#140) turns the #139 policy-admission seam into an explicit fail-closed revocation/freshness/finality posture. `require_revocation_check` and `require_finality` are runtime gates, not descriptive registry labels:

- missing revocation check material rejects as `missing_status` when receiver-held policy requires a revocation check;
- revoked token/status material rejects as `revoked`;
- future status timestamps reject as `stale` instead of satisfying freshness by saturating to age zero;
- `dga1_` authority token expires at the validation instant and rejects as `invalid_admission`;
- required finality without finality material rejects as `not_final`;
- explicit not-final material rejects as `not_final`;
- equivocation material rejects as `equivocated`.

The concrete in-repo implementation remains a bounded fixture/policy seam. Upstream production surfaces are named, not overclaimed: Dregg credentials `expected_revocation_root`, federation `RevocationVerifier` / `RevocationTree`, `ReceiptQc::Threshold` with BLS committee plumbing, and `rotated_replay` / `verify_rotated_replay_chain` are the candidate hardening rails. Any unavailable revocation/finality semantic is a named blockers item and must fail closed or keep production Dregg authority not-ready; it must never silently accept.



## M15.5 / #141 descriptor composition

M15.5 (#141) composes `dregg_authority` into the canonical production `membership.provision` descriptor. The active default manifest now requires all three evidence kinds before a signed context can authorize the operation:

- `wallet_presentation` proves possession of the claimed subject key;
- `membership_credential` proves trusted issuer membership/provisioning evidence under receiver-held issuer/root policy;
- `dregg_authority` proves the bounded Dregg authority policy-admission seam under receiver-held Dregg issuer/root/epoch/status policy.

Wallet plus issuer evidence is no longer sufficient for canonical `membership.provision`; missing `dregg_authority` rejects as `insufficient_evidence`. Conversely, `dregg_authority` alone is never sufficient and cannot bypass receiver-local descriptor, permission, session, replay, TTL, or handler-binding policy. M12.3 shape-only `dregg_receipt` cannot satisfy the production `dregg_authority` requirement.

This issue does not close #73. #159 remains unresolved for live Dregg revocation proof, BLS finality, and rotated-replay proof verification. #160 implements bounded Dregg-provisioned resource locks; #141 binds operation/resource through receiver-local descriptor and request policy only, not Dregg resource-lock authority.


## M15.6 / #142 operator inspection and disclosure boundary

M15.6 (#142) makes `dregg_authority` visible to local operator inspection without leaking raw authority material. The disclosure taxonomy is local operator inspection only and not public auditability:

- summaries label the layer with `authority_class:dregg_authority` and `tier:m15_production_shaped`;
- raw evidence refs are digested as `evidence_ref_sha256`;
- raw `issuer_key_id`, `root_ref`, `epoch_id`, and `federation_id` are digested as `issuer_key_id_sha256`, `root_ref_sha256`, `epoch_id_sha256`, and `federation_id_sha256`;
- stable receiver-held metadata that remains cleartext is limited to fields such as `issuer_id`, `root_fingerprint`, `suite`, `revocation_status`, and `finality_status`;
- raw authority tokens are rendered only as `token:dga1_[redacted]`;
- status/finality fields use stable snake_case values (`active`, `revoked`, `final`, `not_final`, `equivocated`, `not_required`) rather than Rust debug formatting;
- verify receipts and operator receipt inspection preserve the redacted evidence summary under a schema-versioned local ledger projection.

This issue does not implement #159 live Dregg revocation proof, BLS finality, or rotated-replay proof verification. It does not implement #162 live TCP evidence-ref/public-input propagation. It is not deployment proof (#33), public auditability (#37), Midnight (#74), Cardano (#75), or parent #73 closure.

## #73 rewritten acceptance criteria

#73 should now close only when these acceptance criteria are met:

- M15.1 spec exists and is linked from docs indexes and the ready-for-prod checklist.
- `dregg_authority` is a distinct evidence/authority kind from M12.3 `dregg_receipt` and M14 `dregg_backed`.
- Dregg-shaped refs alone remain rejected until a real adapter verifies them.
- Receiver-held production trust policy defines trusted issuer/root material.
- Epoch-scoped federation/root policy is represented where federation authority is claimed.
- Revocation/freshness policy is explicit and stale/revoked decisions fail closed.
- Wrong subject/audience/operation/resource binding rejects.
- Wrong root, wrong epoch, stale/revoked status, malformed token, unsupported suite, and wrong_binding cases produce typed failures.
- Dregg authority composes with wallet proof-of-possession, trusted-issuer credential evidence, receiver-local manifest policy, descriptor-local policy, and receiver-local permission policy.
- Operator receipts/summaries are redaction-safe: they expose reason codes, fingerprints, status, and refs, not raw private tokens/proofs.
- Midnight/Cardano/public auditability/deployment overclaims remain forbidden: #74, #75, #37, and #33 are out of scope unless separate issues implement and verify them.

## Out of scope

Out of scope for M15.1 and not proven by this spec:

- production deployment proof (#33);
- public auditability or public anchoring (#37);
- full Castalia Wallet wallet-core parity (#71), except for composition language with wallet PoP;
- live Castalia registry discovery (#72), unless later promoted explicitly;
- Midnight proof verification (#74);
- Cardano settlement/finality (#75);
- treating local SQLite receipts as public Dregg authority evidence;
- treating caller-supplied roots or root refs as production authority;
- treating M12.3 shape-only or M14 fixture-backed admission as M15 production `dregg_authority`.


#160 implements bounded Dregg-provisioned resource locks: a Dregg authority token may bind an exact verifier-derived trusted requested resource as `resource_lock:verified`, reject mismatches as `resource_lock_violation`, and propagate the locked resource into the signed context for handler/policy use. This is separate from #169 trusted requested-authority attenuation, does not implement live Dregg revocation proof/BLS finality/rotated-replay proof verification, and #159 remains fail-closed blocker posture only. #144/M15.8 reconciles the bounded #73 finalizer.


#144/M15.8 reconciles the bounded #73 finalizer across #162 live ingress evidence refs/public inputs, #167 delegated attenuation / non-amplification, #169 trusted requested-authority attenuation, and #160 implements bounded Dregg-provisioned resource locks. The finalizer preserves `resource_lock:verified` acceptance, `resource_lock_violation` rejection, redaction-safe operator summaries, and signed-context propagation of the verified locked resource for handler/policy use. See `examples/m15-dregg-authority-demo.sh` for the bounded production-shaped demo/checklist. This is not deployment proof, not public auditability, not live Dregg revocation proof, not BLS threshold finality, not rotated-replay proof verification, not Midnight, and not Cardano.
