# One-shot `devgraph.issue.create.v1` Wallet adapter

Status: DG-E2 implemented as a fixed local Wallet ceremony; no Devgraph Work
mutation, deployment, generic browser RPC, `.castaway` read, or hybrid/PQ claim.

Contract: [../specs/devgraph-issue-create-v1.md](../specs/devgraph-issue-create-v1.md)

## Command and fixed boundary

```text
secs-devgraph-issue-create-v1-wallet \
  --request-file <owner-private-raw-issue-json> \
  --idempotency-key-file <owner-private-lf-terminated-file> \
  --signed-projection-output <absent-owner-private-file>
```

These are the only three flags. There is no bind, port, origin, browser,
operation, audience, policy, key, URL, Devgraph, or timeout selector. The
adapter binds only `127.0.0.1:9045` and prints the one fixed URL
`http://127.0.0.1:9045/` once to stderr. It never launches a browser. The user
opens that URL in the Wallet-enabled Chrome profile.

The request file is one strict raw canonical `Issue` JSON object, not the DG-E1
producer envelope. The idempotency file contains one 16–128 character v1 key
and one final LF. The output entry must not exist. All input, output-alias,
fixed receiver-root, replay, clock, and atomic create-only protections are the
same typed implementation used by DG-E1.

## One-shot ceremony

Before listening, the adapter validates the owner-private files and output
boundary. It does not open receiver authority or replay state. Only after the
first valid top-level GET does it create OS-random 16-byte session, 12-byte
nonce, and 32-byte CSRF values in memory. Nothing is placed in a URL, query,
cookie, browser storage, or caller-selected origin.

The state machine is exact:

```text
AwaitingOpen -- exact GET / --> AwaitingWallet
AwaitingWallet -- exact CSRF POST /presentation --> Consuming --> Finished
AwaitingWallet -- exact CSRF POST /cancel --> Finished(cancelled)
```

- `AwaitingOpen` lasts at most 300 seconds.
- The first GET must be HTTP/1.1 for `/` with exact Host and top-level
  `Sec-Fetch-*` bindings. It returns 400 without opening on mismatch.
- The returned page is `no-store`, `nosniff`, `DENY`/`frame-ancestors 'none'`,
  same-origin isolated, and protected by a per-page nonce CSP. All dynamic
  request/ceremony data is base64url-encoded inside one data attribute.
- The page calls only
  `window.castaliaWallet.requestDevgraphIssueCreatePresentation(...)`, directly
  from the button click. It supplies the raw Issue, idempotency key, OS-random
  session/nonce, and a server-issued validity interval no longer than 60
  seconds. Wallet's 65-second page transport grace is not authority validity.
- The `/presentation` and `/cancel` POSTs must have the exact memory-only CSRF header, Host, Origin,
  `Sec-Fetch-*`, `application/json` content type, bounded exact Content-Length,
  and no transfer encoding. A wrong CSRF returns 404 and does not consume. A
  matching CSRF consumes once even if another POST field is malformed. Cancel
  accepts only `{}` and reports the one local `wallet_ceremony_cancelled`
  reason; Wallet/provider exception text is never accepted, echoed, or logged.
- If Wallet is unavailable, rejects, or throws, the page sends the bounded
  `/cancel` request so the CLI finishes instead of waiting for expiry.
- Reloads, duplicate valid-token calls, wrong-state calls, and exact/late expiry
  return 410. The listener closes before any receiver authority file or replay
  database is opened.

After listener closure, the adapter passes the Wallet presentation bytes into
the same crate-private typed DG-P invocation as DG-E1. It writes the same
canonical signed projection bytes through the same held-directory atomic
create-only path. It does not write a presentation/envelope temporary file,
shell out to DG-E1, contact Devgraph, or create an `EventReceipt`.

## Non-claims

This is a local operator ceremony around one Ed25519 v1 operation. It is not a
generic Wallet gateway, login, bearer session, remote HTTP service, public
deployment, Devgraph receiver, Work API, `.castaway` reader, Wallet custody
implementation, service-key generator, or ML-DSA/hybrid/PQ authorization path.
