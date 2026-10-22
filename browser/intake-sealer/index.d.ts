export interface IntakeEnvelopeProfile {
  schema: "service.intake-envelope.v1";
  algorithm: "x25519-hkdf-sha256-chacha20poly1305";
  recipient_key_id: string;
  recipient_public_key_hex: string;
  not_before: string;
  not_after: string;
}

export interface ReferenceObjectEnvelopeProfile {
  schema: "service.reference-object-envelope.v1";
  algorithm: "x25519-hkdf-sha256-chacha20poly1305";
  recipient_key_id: string;
  recipient_public_key_hex: string;
  not_before: string;
  not_after: string;
}

export interface IntakeEnvelopeSealer {
  seal(input: {
    intake: Uint8Array;
    requester_evidence: Uint8Array;
    profile: IntakeEnvelopeProfile;
    expires_at_ms: number;
  }): Promise<Uint8Array>;
  sealReferenceObject(input: {
    request_id: string;
    idempotency_key: string;
    artifact_id: string;
    content_hash: string;
    object: Uint8Array;
    requester_evidence: Uint8Array;
    profile: ReferenceObjectEnvelopeProfile;
    expires_at_ms: number;
  }): Promise<Uint8Array>;
}

export type WasmInitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export function initializeIntakeEnvelopeSealer(moduleOrPath?: WasmInitInput): Promise<void>;
export function createBrowserIntakeEnvelopeSealer(options?: {
  moduleOrPath?: WasmInitInput;
}): Promise<IntakeEnvelopeSealer>;

