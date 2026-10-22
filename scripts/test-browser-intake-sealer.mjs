import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";

const directory = path.resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("package directory argument is required");

const raw = await import(pathToFileURL(path.join(directory, "libsec_core.js")));
const wasm = await readFile(path.join(directory, "libsec_core_bg.wasm"));
raw.initSync({ module: wasm });

const hex = value => Uint8Array.from(value.match(/../gu), pair => Number.parseInt(pair, 16));
const recipientPublic = hex("13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d");
const vector = raw.wasm_seal_intake_envelope_v1(
  recipientPublic,
  new Uint8Array(32).fill(8),
  new Uint8Array(12).fill(9),
  new TextEncoder().encode('{"schema":"service.intake.v1"}'),
  new TextEncoder().encode("signed-membership-proof"),
  2000n,
);
assert.equal(
  createHash("sha256").update(vector).digest("hex"),
  "51e76c5367fb192e9ae967c910dce2dd739797253d34bf762b53f1ad287219e4",
);

const wrapper = await import(pathToFileURL(path.join(directory, "index.js")));
const sealer = await wrapper.createBrowserIntakeEnvelopeSealer({ moduleOrPath: wasm });
const now = Date.now();
const envelope = await sealer.seal({
  intake: new TextEncoder().encode('{"schema":"service.intake.v1"}'),
  requester_evidence: new TextEncoder().encode("evidence"),
  profile: {
    schema: "service.intake-envelope.v1",
    algorithm: "x25519-hkdf-sha256-chacha20poly1305",
    recipient_key_id: "tunnel:x25519:0f6d2553ff0c0f447ae202edd84383e1",
    recipient_public_key_hex: "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d",
    not_before: new Date(now - 1000).toISOString(),
    not_after: new Date(now + 120000).toISOString(),
  },
  expires_at_ms: now + 60000,
});
assert.ok(envelope instanceof Uint8Array);
const keyIdLength = envelope[16];
assert.equal(new TextDecoder().decode(envelope.subarray(17, 17 + keyIdLength)),
  "tunnel:x25519:0f6d2553ff0c0f447ae202edd84383e1");
assert.equal(envelope.some(byte => byte !== 0), true);

