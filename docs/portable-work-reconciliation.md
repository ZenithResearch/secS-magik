# Portable Work/Arena reconciliation

Status: draft review candidate. Source access and installed native acceptance remain
separate release gates. This change does not deploy or provision secS.

## Provenance and boundaries

- Base: public secS main `73d256df006c2b0690b28dd3a0b39568914a4c4c`.
- Retained source: secS `18a6d3a2fa53e7e8a6c40a7dd15c1d79738126e7`:
  portable policy/proof validation and owner-private filesystem operations.
- Shared protocol: public Devgraph `59a0141cefb22f3a5084a13d12c44e1e22f36ab1`.
- Shared presentation: Wallet `52ee41ad03af8f256601c1c21c33e55d876a5380`.
- The portable code is secS's existing MIT-licensed source. No private Wallet
  source or Git history is copied into this repository; it is a pinned dependency.

The portable contract admits the same closed Work and Arena operations as main.
Arena preserves its distinct request digest domain, sorted resource set, previous
Arena bindings and both affected Arena references for membership moves. Existing
Work signing bytes and schema versions remain unchanged. JavaScript does not
reconstruct these bindings.

`secs-devgraph-work-contract` validates public proofs against caller-supplied
current trust. It cannot choose keys, read clocks, issue projections, grant policy,
reserve replay state, dispatch operations or interpret membership as authority.
Native secS still owns current registry checks, service signing and durable replay.
`secs-native-private-files` preserves descriptor-relative owner-private I/O; it
has no alternate authority root. The Packet v0 and admin lifecycle stay intact.

## Reproduction and external gates

Use Rust 1.96.0 from `rust-toolchain.toml` and the committed lockfile:

```sh
cargo test --locked -p secs-devgraph-work-contract --features preserve-order-test
cargo test --locked -p secs-native-private-files
cargo test --locked -p server --test devgraph_work_authority
cargo build --locked -p server --bin secs-devgraph-work-v1
cargo check --locked -p secs-devgraph-work-contract --target wasm32-unknown-unknown
```

Wallet is a private repository. Authorized local remote resolution succeeded using
existing developer Git access. The public protocol declares `AGPL-3.0-only`; the pinned Wallet presentation
manifest declares no package license. Distribution licensing is a separate review
gate, and this extraction does not assign a license to private Wallet source.
Anonymous public builds and this public repository's
CI are **not qualified**; no new CI credential, secret or visibility change is
introduced. Keep this PR draft until source access is settled and the existing
checks pass with approved read-only access. Candidate pins are review pins, not
final release pins.

A real Chrome → native host → secS → guarded receiver acceptance run requires an
isolated runner with disposable identity, policy and receiver data. The existing
local service at port 8080 must remain untouched. Fixtures, portable compilation
and a built CLI do not establish installed-provider or production acceptance.

## Candidate validation

With Rust 1.96.0 and the retained lockfile: five portable proof/hostile-JSON
regressions, three private-file tests and three server authority tests pass.
The authority suite checks exact historical signed Work bytes and current Arena
vectors. Four admin/file unit tests pass; the existing real Wallet workflow test
stays explicitly ignored pending isolated qualification. Portable strict Clippy,
WASM compilation and the native `secs-devgraph-work-v1` build pass. These are scoped
checks for the named Work change; full workspace and hosted CI remain separate.


## Kanban follow-up candidate

Adds workflow.assign, workflow.review and workflow.transition plus the existing
ReviewPacket, Handoff and ExternalLink resource vocabulary to closed policy
admission. Each resource derived from a request still needs an exact or prefix
grant; none is provisioned by this change. The public request and Wallet pins in
Cargo.toml are immutable candidates. Legacy Work/Arena signatures and ZenithPacket
v0 remain unchanged. Native/portable tests use disposable fixtures. Installed
Chrome/native/secS/receiver acceptance and existing source-access gates remain
separate; this does not claim that they passed.
