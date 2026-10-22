import initSecS, {
  wasm_seal_intake_envelope_v1,
  wasm_seal_reference_object_envelope_v1,
} from "./libsec_core.js";

const INTAKE_PROFILE_SCHEMA = "service.intake-envelope.v1";
const REFERENCE_PROFILE_SCHEMA = "service.reference-object-envelope.v1";
const PROFILE_ALGORITHM = "x25519-hkdf-sha256-chacha20poly1305";
const HEX_32 = /^[0-9a-f]{64}$/u;
const VISIBLE_ASCII = /^[!-~]{1,255}$/u;
const INTAKE_MAGIC = new Uint8Array([0x53, 0x45, 0x43, 0x53, 0x49, 0x30, 0x31, 0x00]);
const REFERENCE_MAGIC = new Uint8Array([0x53, 0x45, 0x43, 0x53, 0x52, 0x30, 0x31, 0x00]);
const REFERENCE_IDENTIFIER = /^[!-~]{1,128}$/u;

let initialization;

function copyBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.byteLength !== length)
    throw new TypeError(`${label} must be exactly ${String(length)} bytes`);
  return new Uint8Array(value);
}

function hex32(value, label) {
  if (typeof value !== "string" || !HEX_32.test(value))
    throw new TypeError(`${label} must be 32-byte lowercase hex`);
  return Uint8Array.from(value.match(/../gu), pair => Number.parseInt(pair, 16));
}

function profile(value, expectedSchema, now, expiresAt) {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new TypeError("profile must be an object");
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "algorithm,not_after,not_before,recipient_key_id,recipient_public_key_hex,schema")
    throw new TypeError("profile contains unsupported fields");
  if (value.schema !== expectedSchema || value.algorithm !== PROFILE_ALGORITHM)
    throw new TypeError("profile is unsupported");
  if (typeof value.recipient_key_id !== "string" || !VISIBLE_ASCII.test(value.recipient_key_id))
    throw new TypeError("recipient key identifier is invalid");
  const notBefore = Date.parse(value.not_before);
  const notAfter = Date.parse(value.not_after);
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(expiresAt)
      || !Number.isFinite(notBefore) || !Number.isFinite(notAfter)
      || now < notBefore || now >= notAfter || expiresAt <= now || expiresAt > notAfter)
    throw new TypeError("provider intake key is outside its validity interval");
  return {
    keyId: value.recipient_key_id,
    publicKey: hex32(value.recipient_public_key_hex, "recipient public key"),
  };
}

function inspectHeader(envelope, magic, label) {
  if (!(envelope instanceof Uint8Array) || envelope.byteLength < 65)
    throw new Error(`secS returned a malformed ${label} envelope`);
  if (magic.some((byte, index) => envelope[index] !== byte))
    throw new Error(`secS returned an unsupported ${label} envelope`);
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  const expiresAt = Number(view.getBigUint64(8, false));
  const keyLength = envelope[16];
  const keyEnd = 17 + keyLength;
  if (!Number.isSafeInteger(expiresAt) || keyLength === 0 || keyEnd + 48 > envelope.byteLength)
    throw new Error(`secS returned a malformed ${label} envelope`);
  const keyId = new TextDecoder("utf-8", { fatal: true }).decode(envelope.subarray(17, keyEnd));
  return { expiresAt, keyId };
}

export async function initializeIntakeEnvelopeSealer(moduleOrPath) {
  if (initialization === undefined) {
    initialization = initSecS(moduleOrPath === undefined
      ? undefined
      : { module_or_path: moduleOrPath });
  }
  await initialization;
}

export async function createBrowserIntakeEnvelopeSealer(options = {}) {
  const optionKeys = Object.keys(options).sort().join(",");
  if (optionKeys !== "" && optionKeys !== "moduleOrPath")
    throw new TypeError("sealer options contain unsupported fields");
  await initializeIntakeEnvelopeSealer(options.moduleOrPath);
  return {
    async seal(input) {
      if (typeof input !== "object" || input === null || Array.isArray(input))
        throw new TypeError("seal input must be an object");
      if (Object.keys(input).sort().join(",") !== "expires_at_ms,intake,profile,requester_evidence")
        throw new TypeError("seal input contains unsupported fields");
      const intake = input.intake instanceof Uint8Array ? new Uint8Array(input.intake) : null;
      const evidence = input.requester_evidence instanceof Uint8Array
        ? new Uint8Array(input.requester_evidence) : null;
      if (intake === null || intake.byteLength < 1 || intake.byteLength > 65_536)
        throw new TypeError("intake bytes are outside the secS bound");
      if (evidence === null || evidence.byteLength < 1 || evidence.byteLength > 262_144)
        throw new TypeError("requester evidence is outside the secS bound");
      const now = Date.now();
      const parsed = profile(input.profile, INTAKE_PROFILE_SCHEMA, now, input.expires_at_ms);
      const random = globalThis.crypto;
      if (random === undefined || typeof random.getRandomValues !== "function")
        throw new Error("Web Crypto randomness is unavailable");
      const ephemeralSecret = new Uint8Array(32);
      const nonce = new Uint8Array(12);
      random.getRandomValues(ephemeralSecret);
      random.getRandomValues(nonce);
      try {
        const envelope = new Uint8Array(wasm_seal_intake_envelope_v1(
          parsed.publicKey,
          copyBytes(ephemeralSecret, 32, "ephemeral secret"),
          copyBytes(nonce, 12, "nonce"),
          intake,
          evidence,
          BigInt(input.expires_at_ms),
        ));
        const header = inspectHeader(envelope, INTAKE_MAGIC, "intake");
        if (header.keyId !== parsed.keyId || header.expiresAt !== input.expires_at_ms)
          throw new Error("secS envelope does not match the provider profile");
        return envelope;
      } finally {
        ephemeralSecret.fill(0);
        nonce.fill(0);
      }
    },
    async sealReferenceObject(input) {
      if (typeof input !== "object" || input === null || Array.isArray(input))
        throw new TypeError("reference seal input must be an object");
      if (Object.keys(input).sort().join(",") !==
          "artifact_id,content_hash,expires_at_ms,idempotency_key,object,profile,request_id,requester_evidence")
        throw new TypeError("reference seal input contains unsupported fields");
      for (const [label, value] of [
        ["request_id", input.request_id],
        ["idempotency_key", input.idempotency_key],
        ["artifact_id", input.artifact_id],
      ]) {
        if (typeof value !== "string" || !REFERENCE_IDENTIFIER.test(value))
          throw new TypeError(`${label} is outside the secS bound`);
      }
      const object = input.object instanceof Uint8Array ? new Uint8Array(input.object) : null;
      const evidence = input.requester_evidence instanceof Uint8Array
        ? new Uint8Array(input.requester_evidence) : null;
      if (object === null || object.byteLength < 1 || object.byteLength > 524_288)
        throw new TypeError("reference object bytes are outside the secS bound");
      if (evidence === null || evidence.byteLength < 1 || evidence.byteLength > 262_144)
        throw new TypeError("requester evidence is outside the secS bound");
      const now = Date.now();
      const parsed = profile(input.profile, REFERENCE_PROFILE_SCHEMA, now, input.expires_at_ms);
      const contentHash = hex32(input.content_hash, "reference content hash");
      const random = globalThis.crypto;
      if (random === undefined || typeof random.getRandomValues !== "function")
        throw new Error("Web Crypto randomness is unavailable");
      const ephemeralSecret = new Uint8Array(32);
      const nonce = new Uint8Array(12);
      random.getRandomValues(ephemeralSecret);
      random.getRandomValues(nonce);
      try {
        const envelope = new Uint8Array(wasm_seal_reference_object_envelope_v1(
          parsed.publicKey,
          copyBytes(ephemeralSecret, 32, "ephemeral secret"),
          copyBytes(nonce, 12, "nonce"),
          input.request_id,
          input.idempotency_key,
          input.artifact_id,
          contentHash,
          object,
          evidence,
          BigInt(input.expires_at_ms),
        ));
        const header = inspectHeader(envelope, REFERENCE_MAGIC, "reference object");
        if (header.keyId !== parsed.keyId || header.expiresAt !== input.expires_at_ms)
          throw new Error("secS envelope does not match the provider profile");
        return envelope;
      } finally {
        ephemeralSecret.fill(0);
        nonce.fill(0);
      }
    },
  };
}

