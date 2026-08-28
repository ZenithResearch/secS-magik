# WASM and GitHub Pages reference

Status: current reference for the bounded browser/WASM surfaces and documentation delivery. Publishing these artifacts does not create a remote administration plane or production service.

## WASM surfaces

### Core tunnel bindings

`libsec-core` is normally `no_std` when its optional `uniffi` feature is disabled. With the feature enabled for `wasm32-unknown-unknown`, `core/src/ffi.rs` exposes two wasm-bindgen functions:

```text
wasm_encrypt(key_bytes, nonce_bytes, plaintext, aad) -> ciphertext
wasm_decrypt(key_bytes, nonce_bytes, ciphertext, aad) -> plaintext | error
```

The functions delegate to the same ChaCha20Poly1305 helpers used by core. Inputs are caller-supplied:

- key: exactly 32 bytes;
- nonce: exactly 12 bytes;
- associated data: caller-provided bytes, normally the canonical packet AAD;
- plaintext/ciphertext: byte arrays.

The wrapper does not generate, store, distribute, rotate, or authorize keys. Invalid key/nonce lengths trap through the current exact-length assertions; authentication failure returns `decryption failed` without plaintext.

Build/check commands:

```bash
rustup target add wasm32-unknown-unknown
cargo check -p libsec-core --target wasm32-unknown-unknown --features uniffi
cargo doc -p libsec-core --target wasm32-unknown-unknown --features uniffi --no-deps
```

### Receiver-local permission panel

`panel` is a wasm-bindgen wrapper over `secs-permissions`. It exports:

| Function | Effect |
|---|---|
| `grant` | Append an allow or deny record and return updated pretty JSON. |
| `revoke` | Mark exact caller/opcode/operation/resource matches revoked. |
| `evaluate` | Return `ALLOW` or `DENY:<reason>` for one request/time. |
| `list` | Return newline-separated human-readable record summaries. |

`panel/www/index.html` and `panel/www/panel.js` provide the UI. The policy is kept as JSON in browser `localStorage`. There is no fetch/WebSocket/API client, no gateway key, and no server synchronization.

Security boundary:

- The panel is an authoring/evaluation aid for the same data model enforced by a gateway after an operator installs a policy file.
- Browser state does not modify a running gateway.
- Folder/file pickers are visual resource-name helpers; the panel does not read, write, execute, or upload chosen files.
- The UI demonstrates receiver-local policy and carries no Dregg authority, deployment proof, or public-auditability claim.

Local build:

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build panel --target web --out-dir www/pkg --out-name panel
python3 -m http.server --directory panel/www 8000
```

`wasm-pack` writes generated JavaScript, TypeScript declarations, package metadata, and the `.wasm` binary to `panel/www/pkg`. That directory is a build artifact and is not committed.

## Documentation site contract

The GitHub Pages site is assembled by `scripts/build-pages.sh` and deployed by `.github/workflows/pages.yml`.

Published routes:

| Route | Source |
|---|---|
| `/secS-magik/` | Root `README.md`, copied to generated `index.md` and rendered by Jekyll. |
| `/secS-magik/docs/` | Tracked Markdown documentation with generated front matter. |
| `/secS-magik/api/` | `cargo doc --workspace --all-features --no-deps` on the host target. |
| `/secS-magik/wasm-api/` | wasm32 rustdoc for `libsec-core` with `uniffi` plus `panel`. |
| `/secS-magik/panel/` | `panel/www` plus a release `wasm-pack --target web` build. |

The source tree remains authoritative. Generated site, rustdoc, JavaScript glue, and `.wasm` outputs are assembled in a caller-selected build directory and are never staged as repository source.

### Local assembly

```bash
./scripts/build-pages.sh .pages/source
```

This command:

1. validates the destination and recreates only that destination;
2. derives the site home from the root README;
3. copies current documentation/readme surfaces and adds Jekyll front matter in the generated tree;
4. generates host Rust API documentation;
5. generates wasm32 Rust API documentation;
6. builds the browser permission panel into the generated site tree.

The GitHub workflow then runs the official Jekyll Pages builder, uploads the static artifact, and deploys only from `main` or a manual workflow run. Pull requests perform the full build but do not deploy.

### Site does not widen authority

The Pages artifact contains only tracked public documentation, generated public API docs, and the no-network permission panel. The build must never copy:

- environment files;
- caller, verifier, tunnel, or bearer-token secrets;
- local SQLite databases;
- packet captures;
- runtime logs;
- private evidence or operator configuration;
- arbitrary workspace files.

GitHub Pages availability is documentation hosting, not production gateway availability. A published audit format or panel does not make local receipts publicly immutable and does not create live federation authority.
