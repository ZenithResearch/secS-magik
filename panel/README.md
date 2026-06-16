# panel — WASM browser permission control panel (M13.4b)

A vanilla (no-framework) browser control panel for **receiver-local** secS
permissions. It compiles the shared [`secs-permissions`](../permissions) model
to WebAssembly via `wasm-bindgen` and drives it from plain HTML/JS — the same
model the gateway enforces and the [`secs-permctl`](../server/src/bin/secs-permctl.rs)
CLI authors.

The policy lives entirely in the browser (`localStorage`). There is **no server
and no network**: this is local receiver-local policy authoring and evaluation
only. It makes no Dregg authority, deployment-proof, or public-auditability
claims.

## What it does

- **Grant** a permission record (caller × opcode × operation × resource scope,
  exact or prefix, allow or deny, validity window).
- **Revoke** matching records.
- **Evaluate** a request and see `ALLOW` / `DENY:<reason>` in the decision feed.
- View the current policy.

## Build

The WASM module is generated, not committed (`www/pkg/` is gitignored). Build it
with [`wasm-pack`](https://drager.github.io/wasm-pack/):

```bash
# from the repo root
wasm-pack build panel --target web --out-dir www/pkg
```

## Run

Serve the `panel/www` directory over HTTP (ES modules + wasm cannot load from
`file://`):

```bash
cd panel/www
python3 -m http.server 8000
# open http://localhost:8000
```

## API (wasm-bindgen exports)

`panel/src/lib.rs` exposes JSON-in / JSON-out functions over a policy string:

- `grant(policy, caller, opcode, operation, resource, prefix, deny, not_before, not_after) -> policy`
- `revoke(policy, caller, opcode, operation, resource) -> policy`
- `evaluate(policy, caller, opcode, operation, resource, now) -> "ALLOW" | "DENY:<reason>"`
- `list(policy) -> newline-separated record summaries`

The wasm32 build is checked in CI (`cargo check -p panel --target wasm32-unknown-unknown`).
