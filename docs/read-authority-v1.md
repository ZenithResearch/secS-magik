# Holder-bound read authority v1

Status: source candidate with separately recorded disposable receiver/browser/iPad
evidence. This source snapshot alone does not qualify any deployed host or the
DevGraph write chain. Exact-commit CI and installed release checks remain gates.

`tools/read-authority` builds `secs-read-authority-v1`. Its shared contract is a
checksum-pinned copy of Wallet's MIT `castalia-wallet-presentation` crate. Run
`python3 tools/read-authority/verify-source.py /path/to/castalia-wallet` to check
the coordinated source. `SOURCE.json` pins the reviewed Wallet commit and seven exact source hashes,
including the shared validity helper used by the finite read-credential parser.
The standalone workspace preserves existing secS dependency pins and packet v0.

The issuer accepts only permissions in its explicit owner-private policy. It
signs `castalia.read-credential.v1`, binding holder, device, receiver, audience,
policy digest, exact permissions and a maximum one-hour lifetime. This is a new
contract: request-credential v1, credential-presentation v2, Dregg membership
credentials and historical signing domains retain their existing meanings.

Wallet confirms the disclosure and issuer pin, verifies the credential, and
produces a fresh `castalia.read-presentation.v1` for each exact read call. secS
verifies its signature, policy, operation/resource, holder, receiver and expiry.
The receiver's trusted registry adapter supplies current credential and
membership revocation status; it atomically consumes each verified nonce before
dispatch. Network callers cannot supply that registry status. Credential renewal
does not widen the stored enrollment ceiling. There is no child delegation.

Devgraph owns the grant vocabulary and Arena/resource interpretation. Its typed
adapter enforces selectors before pagination. The generic library does not
understand Projects, Arenas, or Work mutations. No application-specific read
credential is substituted when secS is missing.

## Build and verification

```sh
cargo build --locked --offline --manifest-path tools/read-authority/Cargo.toml
cargo test --locked --offline --manifest-path tools/read-authority/Cargo.toml
cargo test --locked --offline --manifest-path tools/read-authority/vendor/castalia-wallet-presentation/Cargo.toml
python3 tools/read-authority/verify-source.py
cargo test --workspace
cargo build --workspace
```

The executable reads one bounded JSON command from its trusted host's stdin and
returns a safe JSON result. `--policy-file` is mandatory. Only issuance accepts
`--issuer-key-file`; verification receives no issuer private key. Both files must
be regular, owner-private, non-symlink files. No auto-discovery, provisioning,
trust installation or grant expansion occurs. The host must use the current
registry and consume replay state, never expose this stdin interface directly to
an untrusted app or network caller.

## Operator identity and shared endpoint direction

The current DevGraph MVP authorizes operator Wallet public keys from receiver-held
policy and verifies an exact Wallet proof for each administrative action. A separate
admin credential is not required by that flow. Generic credential-backed
administration is follow-on work; see the
[shared endpoint integration plan](plans/2026-10-21-shared-wallet-resource-endpoint.md).
HTTPS transport, issuer trust and server policy still require explicit deployment
configuration. This CLI is not itself a network listener.
