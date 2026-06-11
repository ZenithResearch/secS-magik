#![cfg_attr(not(feature = "uniffi"), no_std)]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[cfg(feature = "uniffi")]
pub mod ffi;
// uniffi 0.28 requires scaffolding setup at the crate root (it references
// `crate::UniFfiTag`); keep it scoped to the wasm32 surface like `ffi`.
#[cfg(all(feature = "uniffi", target_arch = "wasm32"))]
uniffi::setup_scaffolding!();
pub mod caller_proof;
pub mod packet_builder;
pub mod response;
pub mod tunnel;
pub mod zk;

pub const OPCODE_GENERATE: u8 = 0x01;
pub const OPCODE_CHAT: u8 = 0x02;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[repr(C)]
pub struct ZenithPacket {
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub proof: Vec<u8>,
    pub claim_ttl: u64,
    pub encrypted_payload: Vec<u8>,
    /// Reserved (M12.6, option b): kept only for v0 byte-layout
    /// compatibility. Current clients zero it and the server never reads it.
    /// It carries **no authentication** — caller authenticity comes from the
    /// caller proof-of-origin envelope in `proof` (M12.1) and payload
    /// integrity from tunnel AEAD binding (M12.4). Any future real MAC or
    /// removal is an explicit, owned wire-format migration.
    pub mac: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[repr(C)]
pub struct SessionHandshake {
    pub ephemeral_public_key: [u8; 32],
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample_packet() -> ZenithPacket {
        ZenithPacket {
            session_id: [0xAA; 16],
            nonce: [0xBB; 12],
            opcode: OPCODE_GENERATE,
            proof: vec![0xCC; 64],
            claim_ttl: 3600,
            encrypted_payload: vec![0xDD; 128],
            mac: [0xEE; 16],
        }
    }

    #[test]
    fn reserved_mac_field_keeps_v0_layout_for_any_value() {
        // Option (b) compatibility pin: zeroed (current clients) and legacy
        // nonzero mac bytes both round-trip with the unchanged v0 layout, so
        // receipts/hashes computed over old packets still decode/inspect.
        for mac in [[0u8; 16], [0xEE; 16]] {
            let packet = ZenithPacket {
                mac,
                ..sample_packet()
            };
            let bytes = bincode::serialize(&packet).unwrap();
            // mac is the final field of the v0 layout: the serialized frame
            // ends with exactly its 16 bytes.
            assert_eq!(&bytes[bytes.len() - 16..], &mac);
            let decoded: ZenithPacket = bincode::deserialize(&bytes).unwrap();
            assert_eq!(decoded, packet);
        }
    }

    #[test]
    fn test_zenith_packet_serialization() {
        let packet = sample_packet();

        let bytes = bincode::serialize(&packet).unwrap();
        let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_session_handshake_serialization() {
        let handshake = SessionHandshake {
            ephemeral_public_key: [0xFF; 32],
            timestamp: 1234567890,
        };

        let bytes = bincode::serialize(&handshake).unwrap();
        let deserialized: SessionHandshake = bincode::deserialize(&bytes).unwrap();

        assert_eq!(handshake, deserialized);
    }

    #[test]
    fn test_handshake_in_encrypted_payload() {
        let mut encrypted_payload = vec![0x01; 32];
        encrypted_payload.extend_from_slice(&[0x02]);

        let packet = ZenithPacket {
            session_id: [0xAA; 16],
            nonce: [0xBB; 12],
            opcode: OPCODE_CHAT,
            proof: vec![],
            claim_ttl: 3600,
            encrypted_payload,
            mac: [0x00; 16],
        };

        let bytes = bincode::serialize(&packet).unwrap();
        let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

        assert_eq!(
            packet.encrypted_payload.len(),
            deserialized.encrypted_payload.len()
        );
    }

    #[test]
    fn zenith_packet_round_trips_empty_proof_and_empty_payload() {
        let packet = ZenithPacket {
            session_id: [0; 16],
            nonce: [0; 12],
            opcode: 0,
            proof: vec![],
            claim_ttl: 0,
            encrypted_payload: vec![],
            mac: [0; 16],
        };

        let bytes = bincode::serialize(&packet).unwrap();
        let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

        assert_eq!(packet, deserialized);
    }

    #[test]
    fn zenith_packet_round_trips_maximum_opcode() {
        let mut packet = sample_packet();
        packet.opcode = u8::MAX;

        let bytes = bincode::serialize(&packet).unwrap();
        let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.opcode, u8::MAX);
    }

    #[test]
    fn zenith_packet_deserialization_rejects_truncated_bytes() {
        let packet = sample_packet();
        let mut bytes = bincode::serialize(&packet).unwrap();
        bytes.truncate(bytes.len() / 2);

        let err = bincode::deserialize::<ZenithPacket>(&bytes).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn session_handshake_preserves_timestamp_boundaries() {
        for timestamp in [0, 1, u64::MAX] {
            let handshake = SessionHandshake {
                ephemeral_public_key: [0x42; 32],
                timestamp,
            };

            let bytes = bincode::serialize(&handshake).unwrap();
            let deserialized: SessionHandshake = bincode::deserialize(&bytes).unwrap();

            assert_eq!(deserialized.timestamp, timestamp);
        }
    }
}
