# Reusable same-holder grants v1

Status: initial source implementation, not deployed. Tracking boundary:
DevGraph Issue `castalia-devgraph-local-delegated-read`.

`crates/secs-grant-contract` defines three independent signature domains:
provider-signed `secs.holder-grant.v1`, holder-signed
`secs.holder-credential.v1`, and exact-call-bound
`secs.holder-presentation.v1`. Packet v0 and old read credentials are unchanged.
The standalone crate is consumed identically by native and WASM Wallet Core;
product UI does not perform independent cryptographic validation.

The root binds an issuer/key, canonical service, holder, optional installation,
registry revision, explicit dated/until-revoked validity, correlated permissions
and maximum derived lifetime. It contains no transport URL. Issuer trust and
origin approval are separate. The recipient reviews and saves the signed root
in encrypted backed-up Wallet storage. A derived credential embeds the root,
references its digest and is signed by exactly the same holder. Permissions can
be equal, removed, or narrowed by selecting descendant path roots. Other opaque
constraint records must remain identical; this version makes no arbitrary
application-predicate implication claim. No Cartesian product is constructed.
Onward delegation is unconditionally disabled; unknown fields and child-chain
shapes fail closed. All credentials have finite lifetime, at most one hour and
within their root's bounds. Current-subtree roots are evaluated by the resource
provider against actual ancestry at access time, not by string-prefix matching
against a network URL.

`tools/holder-grant-authority` is an explicit owner-private stdin/stdout adapter.
Its issuer pin and signing key come only from fixed trusted provider configuration.
It opens no listener and discovers no keys. Its verify result attests signatures,
time and attenuation only. The provider MUST independently resolve the current
root digest/revision, current assignment, membership policy if required, expiry,
revocation and narrowing. It MUST atomically consume proof nonces in its durable
replay ledger before exposing data or executing mutations. The output is not an
execution context, receipt, active-status attestation or bypass of these gates.
The caller must enforce the returned correlated resource constraints.

The initial Rust tests cover equal scope, descendant scope, scope widening,
wrong holder, onward delegation, tampered signatures, expiry, service substitution,
call binding, duplicate fields and parent validity. Full cross-repository storage,
UI, native/WASM, receiver, restart/revocation and installed Tailscale qualification
remain required. Source tests alone do not qualify a production deployment.

Wire bounds: root claims are at most61,440 canonical UTF-8 bytes. Opaque conditions reserve eight nesting levels for their enclosing chain. Complete credentials fit131,072 bytes; emitted presentation envelopes fit130,000 bytes, reserving space for the native verifier request wrapper. A root at this limit can still derive an equal-scope child. Oversized calls fail before a presentation is returned.
