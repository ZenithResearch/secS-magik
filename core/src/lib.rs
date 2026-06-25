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
pub mod ingress_request;
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
    use crate::ingress_request::{
        decode_ingress_frame, encode_ingress_request_v1, IngressFrame, IngressRequestV1,
        MAX_EVIDENCE_INPUTS, MAX_EVIDENCE_INPUT_BYTES,
    };
    use alloc::format;
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
    fn ingress_request_v1_round_trips_packet_refs_and_public_inputs() {
        let request = IngressRequestV1::new(
            sample_packet(),
            vec![
                "wallet-ref".to_string(),
                "credential-ref".to_string(),
                "wallet-ref".to_string(),
            ],
            vec!["origin:https://example.test".to_string()],
        );

        let bytes = encode_ingress_request_v1(&request).unwrap();
        match decode_ingress_frame(&bytes, bytes.len()).unwrap() {
            IngressFrame::V1(decoded) => {
                assert_eq!(decoded.packet, request.packet);
                assert_eq!(decoded.evidence_refs, vec!["wallet-ref", "credential-ref"]);
                assert_eq!(decoded.public_inputs, vec!["origin:https://example.test"]);
            }
            IngressFrame::Legacy(_) => {
                panic!("versioned ingress request must not decode as legacy packet")
            }
        }
    }

    #[test]
    fn ingress_request_v1_rejects_unbounded_evidence_metadata() {
        let too_many = IngressRequestV1::new(
            sample_packet(),
            (0..=MAX_EVIDENCE_INPUTS)
                .map(|i| format!("evidence-{i}"))
                .collect(),
            vec![],
        );
        assert!(encode_ingress_request_v1(&too_many).is_err());

        let too_large = IngressRequestV1::new(
            sample_packet(),
            vec!["x".repeat(MAX_EVIDENCE_INPUT_BYTES + 1)],
            vec![],
        );
        assert!(encode_ingress_request_v1(&too_large).is_err());
    }

    #[test]
    fn legacy_packet_decodes_as_legacy_ingress_frame() {
        let packet = sample_packet();
        let bytes = bincode::serialize(&packet).unwrap();
        match decode_ingress_frame(&bytes, bytes.len()).unwrap() {
            IngressFrame::Legacy(decoded) => assert_eq!(decoded, packet),
            IngressFrame::V1(_) => panic!("bare ZenithPacket must remain v0-compatible"),
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
