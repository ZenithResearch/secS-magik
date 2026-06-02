use crate::ZenithPacket;
use alloc::vec::Vec;

/// Verifier-free builder for the v0 `ZenithPacket` envelope.
///
/// This helper only preserves caller-provided packet fields. It deliberately
/// does not validate capabilities, credentials, evidence, authority, replay,
/// expiry, or receipt semantics. Server-side secS verifier code remains
/// responsible for deciding whether a constructed packet is acceptable.
#[must_use]
#[derive(Debug, Clone, PartialEq)]
pub struct PacketBuilder {
    session_id: [u8; 16],
    nonce: [u8; 12],
    opcode: u8,
    proof: Vec<u8>,
    claim_ttl: u64,
    encrypted_payload: Vec<u8>,
    mac: [u8; 16],
}

impl PacketBuilder {
    /// Create a raw packet builder with zero/empty field defaults.
    ///
    /// The defaults are useful for tests and prototype callers, but they are
    /// not proof of verifier acceptance. Production callers should set every
    /// field according to their session, presentation/proof, payload, and MAC
    /// or tunnel policy before submitting to secS.
    pub fn new() -> Self {
        Self {
            session_id: [0; 16],
            nonce: [0; 12],
            opcode: 0,
            proof: Vec::new(),
            claim_ttl: 0,
            encrypted_payload: Vec::new(),
            mac: [0; 16],
        }
    }

    pub fn session_id(mut self, session_id: [u8; 16]) -> Self {
        self.session_id = session_id;
        self
    }

    pub fn nonce(mut self, nonce: [u8; 12]) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn opcode(mut self, opcode: u8) -> Self {
        self.opcode = opcode;
        self
    }

    pub fn proof(mut self, proof: impl Into<Vec<u8>>) -> Self {
        self.proof = proof.into();
        self
    }

    pub fn claim_ttl(mut self, claim_ttl: u64) -> Self {
        self.claim_ttl = claim_ttl;
        self
    }

    pub fn encrypted_payload(mut self, encrypted_payload: impl Into<Vec<u8>>) -> Self {
        self.encrypted_payload = encrypted_payload.into();
        self
    }

    pub fn mac(mut self, mac: [u8; 16]) -> Self {
        self.mac = mac;
        self
    }

    /// Build a `ZenithPacket` without performing verifier or authority checks.
    pub fn build(self) -> ZenithPacket {
        ZenithPacket {
            session_id: self.session_id,
            nonce: self.nonce,
            opcode: self.opcode,
            proof: self.proof,
            claim_ttl: self.claim_ttl,
            encrypted_payload: self.encrypted_payload,
            mac: self.mac,
        }
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZenithPacket;
    use alloc::vec;

    #[test]
    fn packet_builder_preserves_v0_fields_and_decimal_opcode_values() {
        let packet = PacketBuilder::new()
            .session_id([0x11; 16])
            .nonce([0x22; 12])
            .opcode(16)
            .proof([0x33, 0x44])
            .claim_ttl(60)
            .encrypted_payload([0x55, 0x66])
            .mac([0x77; 16])
            .build();

        assert_eq!(packet.session_id, [0x11; 16]);
        assert_eq!(packet.nonce, [0x22; 12]);
        assert_eq!(packet.opcode, 16);
        assert_eq!(packet.proof, vec![0x33, 0x44]);
        assert_eq!(packet.claim_ttl, 60);
        assert_eq!(packet.encrypted_payload, vec![0x55, 0x66]);
        assert_eq!(packet.mac, [0x77; 16]);
    }

    #[test]
    fn packet_builder_is_verifier_free_and_allows_serializable_empty_verifier_inputs() {
        let packet = PacketBuilder::new()
            .session_id([0; 16])
            .nonce([0; 12])
            .opcode(255)
            .proof(Vec::new())
            .claim_ttl(0)
            .encrypted_payload(Vec::new())
            .mac([0; 16])
            .build();

        let expected = ZenithPacket {
            session_id: [0; 16],
            nonce: [0; 12],
            opcode: 255,
            proof: vec![],
            claim_ttl: 0,
            encrypted_payload: vec![],
            mac: [0; 16],
        };
        assert_eq!(packet, expected);

        let bytes = bincode::serialize(&packet).unwrap();
        let round_trip: ZenithPacket = bincode::deserialize(&bytes).unwrap();
        assert_eq!(round_trip, packet);
    }
}
