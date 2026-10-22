# Frank connector-result authority

The Frank connector-result authority turns one retained, unsigned Matrix or Hermes connector observation into a native `frank.result.attest.v1` envelope. It is a fixed local authority boundary: the executable reopens the selected Frank SQLite journal, revalidates the exact capture and connector policy, and signs only after its receiver-held assignment and private ledger checks pass.

This component does not call a provider, schedule a process, admit a Runtime completion, or make Matrix/Hermes identity authoritative. Frank retains and selects the observation; secS independently validates and attests it; the receiving Runtime still verifies the returned envelope under its own policy.

## Binaries

`secs-frank-connector-result-setup` creates one authority bundle from a canonical, SHA-256-pinned JSON plan:

```text
secs-frank-connector-result-setup \
  --plan /absolute/private/setup-plan.json \
  --plan-sha256 <64-lowercase-hex>
```

The plan schema is `secs.frank.connector-result-setup-plan.v1`. It binds the absolute authority root and Frank journal, actor, integration, fixed `local` route, permitted run/resource pairs, producer/configuration/normalizer/source pins, and a validity window no longer than four hours.

Creation publishes these owner-private files:

- `issuer/`: generated Ed25519 seed plus stable lock;
- `assignment/assignment.json`: the exact connector result-party assignment;
- `config/authority.json`: the native authority configuration;
- `config/producer.json`: Frank's pinned native producer configuration;
- `config/receiver-policy.json`: the corresponding Runtime verification policy;
- `COMPLETE.json`: hashes and bounds for the completed setup.

All directories are private and all files are create-only. A retry against an existing or partially-created root rejects without replacing existing bytes. The generated seed never appears in stdout or setup metadata.

`secs-frank-connector-result` accepts an exact canonical selector on stdin:

```text
secs-frank-connector-result attest \
  --config /absolute/private/config/authority.json \
  --config-sha256 <64-lowercase-hex>
```

The supported modes are `attest`, `resume`, and `renew`. Stdin is limited to 16 KiB. Successful stdout contains only the bounded native result envelope; failures collapse to `native_connector_result_authority_rejected` and exit status 2.

## Validation boundary

Before signing, the authority checks the exact owner configuration and its digest, private issuer/assignment/capture/ledger roots, active assignment window and scope, connector policy digest, retained delivery and dispatch rows, work/result/payload/provenance/original hashes, actor/integration/route/run/resource bindings, allowed operation, source manifest and producer pins, and the private ledger's replay and renewal chain.

`resume` can finish only a selector already retained by Frank. `renew` must name the hash of the completed prior envelope and preserves the original capture lineage. Changed capture bytes, an unsupported mode, a wrong policy or configuration pin, an unassigned run/resource, replay, or an invalid renewal tip fails before a new envelope is returned.

## Local verification

```bash
cargo test -p server --test frank_connector_result_authority
cargo build -p server \
  --bin secs-frank-connector-result \
  --bin secs-frank-connector-result-setup
cargo test --workspace
cargo build --workspace
```

Passing repository tests and a disposable setup smoke prove the source behavior. They do not establish that a published release, installed bundle, live Frank composition, or Runtime receiver policy uses the resulting artifacts; those remain separate release and production-acceptance evidence.
