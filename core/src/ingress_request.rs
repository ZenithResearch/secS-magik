use crate::ZenithPacket;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const INGRESS_REQUEST_V1_MAGIC: &[u8; 8] = b"SECSRQ1\0";
pub const INGRESS_REQUEST_V2_MAGIC: &[u8; 8] = b"SECSRQ2\0";
pub const MAX_EVIDENCE_INPUTS: usize = 16;
pub const MAX_EVIDENCE_INPUT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressRequestError {
    FrameTooLarge,
    Malformed,
    TooManyEvidenceInputs,
    EvidenceInputTooLarge,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IngressRequestV1 {
    pub packet: ZenithPacket,
    pub evidence_refs: Vec<String>,
    pub public_inputs: Vec<String>,
}

impl IngressRequestV1 {
    pub fn new(
        packet: ZenithPacket,
        evidence_refs: Vec<String>,
        public_inputs: Vec<String>,
    ) -> Self {
        Self {
            packet,
            evidence_refs: dedupe_preserving_order(evidence_refs),
            public_inputs,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IngressRequestV2 {
    pub packet: ZenithPacket,
    pub evidence_refs: Vec<String>,
    pub public_inputs: Vec<String>,
    pub client_ephemeral_public_key: [u8; 32],
}

impl IngressRequestV2 {
    pub fn new(
        packet: ZenithPacket,
        evidence_refs: Vec<String>,
        public_inputs: Vec<String>,
        client_ephemeral_public_key: [u8; 32],
    ) -> Self {
        Self {
            packet,
            evidence_refs: dedupe_preserving_order(evidence_refs),
            public_inputs,
            client_ephemeral_public_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IngressFrame {
    Legacy(ZenithPacket),
    V1(IngressRequestV1),
    V2(IngressRequestV2),
}

pub fn encode_ingress_request_v1(
    request: &IngressRequestV1,
) -> Result<Vec<u8>, IngressRequestError> {
    validate_inputs(&request.evidence_refs)?;
    validate_inputs(&request.public_inputs)?;

    let packet_bytes =
        bincode::serialize(&request.packet).map_err(|_| IngressRequestError::Malformed)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INGRESS_REQUEST_V1_MAGIC);
    push_len(&mut bytes, packet_bytes.len())?;
    bytes.extend_from_slice(&packet_bytes);
    push_string_vec(&mut bytes, &request.evidence_refs)?;
    push_string_vec(&mut bytes, &request.public_inputs)?;
    Ok(bytes)
}

pub fn encode_ingress_request_v2(
    request: &IngressRequestV2,
) -> Result<Vec<u8>, IngressRequestError> {
    validate_inputs(&request.evidence_refs)?;
    validate_inputs(&request.public_inputs)?;

    let packet_bytes =
        bincode::serialize(&request.packet).map_err(|_| IngressRequestError::Malformed)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INGRESS_REQUEST_V2_MAGIC);
    push_len(&mut bytes, packet_bytes.len())?;
    bytes.extend_from_slice(&packet_bytes);
    push_string_vec(&mut bytes, &request.evidence_refs)?;
    push_string_vec(&mut bytes, &request.public_inputs)?;
    bytes.extend_from_slice(&request.client_ephemeral_public_key);
    Ok(bytes)
}

pub fn decode_ingress_frame(
    bytes: &[u8],
    max_frame_bytes: usize,
) -> Result<IngressFrame, IngressRequestError> {
    if bytes.len() > max_frame_bytes {
        return Err(IngressRequestError::FrameTooLarge);
    }

    if bytes.starts_with(INGRESS_REQUEST_V2_MAGIC) {
        let mut offset = INGRESS_REQUEST_V2_MAGIC.len();
        let packet_len = read_len(bytes, &mut offset)?;
        if packet_len > max_frame_bytes || offset.checked_add(packet_len).is_none() {
            return Err(IngressRequestError::FrameTooLarge);
        }
        let packet_end = offset + packet_len;
        let packet = bincode::deserialize::<ZenithPacket>(
            bytes
                .get(offset..packet_end)
                .ok_or(IngressRequestError::Malformed)?,
        )
        .map_err(|_| IngressRequestError::Malformed)?;
        offset = packet_end;
        let evidence_refs = read_string_vec(bytes, &mut offset)?;
        let public_inputs = read_string_vec(bytes, &mut offset)?;
        let key_end = offset
            .checked_add(32)
            .ok_or(IngressRequestError::Malformed)?;
        let client_ephemeral_public_key: [u8; 32] = bytes
            .get(offset..key_end)
            .ok_or(IngressRequestError::Malformed)?
            .try_into()
            .map_err(|_| IngressRequestError::Malformed)?;
        offset = key_end;
        if offset != bytes.len() {
            return Err(IngressRequestError::Malformed);
        }
        return Ok(IngressFrame::V2(IngressRequestV2::new(
            packet,
            evidence_refs,
            public_inputs,
            client_ephemeral_public_key,
        )));
    }

    if !bytes.starts_with(INGRESS_REQUEST_V1_MAGIC) {
        let packet = bincode::deserialize::<ZenithPacket>(bytes)
            .map_err(|_| IngressRequestError::Malformed)?;
        return Ok(IngressFrame::Legacy(packet));
    }

    let mut offset = INGRESS_REQUEST_V1_MAGIC.len();
    let packet_len = read_len(bytes, &mut offset)?;
    if packet_len > max_frame_bytes || offset.checked_add(packet_len).is_none() {
        return Err(IngressRequestError::FrameTooLarge);
    }
    let packet_end = offset + packet_len;
    let packet = bincode::deserialize::<ZenithPacket>(
        bytes
            .get(offset..packet_end)
            .ok_or(IngressRequestError::Malformed)?,
    )
    .map_err(|_| IngressRequestError::Malformed)?;
    offset = packet_end;
    let evidence_refs = read_string_vec(bytes, &mut offset)?;
    let public_inputs = read_string_vec(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(IngressRequestError::Malformed);
    }
    Ok(IngressFrame::V1(IngressRequestV1::new(
        packet,
        evidence_refs,
        public_inputs,
    )))
}

fn validate_inputs(inputs: &[String]) -> Result<(), IngressRequestError> {
    if inputs.len() > MAX_EVIDENCE_INPUTS {
        return Err(IngressRequestError::TooManyEvidenceInputs);
    }
    if inputs
        .iter()
        .any(|input| input.len() > MAX_EVIDENCE_INPUT_BYTES)
    {
        return Err(IngressRequestError::EvidenceInputTooLarge);
    }
    Ok(())
}

fn push_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), IngressRequestError> {
    let len = u64::try_from(len).map_err(|_| IngressRequestError::FrameTooLarge)?;
    bytes.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn read_len(bytes: &[u8], offset: &mut usize) -> Result<usize, IngressRequestError> {
    let end = offset
        .checked_add(8)
        .ok_or(IngressRequestError::Malformed)?;
    let raw: [u8; 8] = bytes
        .get(*offset..end)
        .ok_or(IngressRequestError::Malformed)?
        .try_into()
        .map_err(|_| IngressRequestError::Malformed)?;
    *offset = end;
    usize::try_from(u64::from_le_bytes(raw)).map_err(|_| IngressRequestError::FrameTooLarge)
}

fn push_string_vec(bytes: &mut Vec<u8>, values: &[String]) -> Result<(), IngressRequestError> {
    push_len(bytes, values.len())?;
    for value in values {
        push_len(bytes, value.len())?;
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

fn read_string_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<String>, IngressRequestError> {
    let count = read_len(bytes, offset)?;
    if count > MAX_EVIDENCE_INPUTS {
        return Err(IngressRequestError::TooManyEvidenceInputs);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_len(bytes, offset)?;
        if len > MAX_EVIDENCE_INPUT_BYTES {
            return Err(IngressRequestError::EvidenceInputTooLarge);
        }
        let end = offset
            .checked_add(len)
            .ok_or(IngressRequestError::Malformed)?;
        let value = core::str::from_utf8(
            bytes
                .get(*offset..end)
                .ok_or(IngressRequestError::Malformed)?,
        )
        .map_err(|_| IngressRequestError::Malformed)?
        .to_string();
        *offset = end;
        values.push(value);
    }
    Ok(values)
}

fn dedupe_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.iter().any(|existing| existing == &value) {
            deduped.push(value);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn packet() -> ZenithPacket {
        ZenithPacket {
            session_id: [1u8; 16],
            nonce: [2u8; 12],
            opcode: 0x10,
            proof: vec![3],
            claim_ttl: 300,
            encrypted_payload: vec![4, 5],
            mac: [0u8; 16],
        }
    }

    #[test]
    fn ingress_request_v2_round_trips_client_ephemeral_key() {
        let request = IngressRequestV2::new(
            packet(),
            vec!["ref:a".to_string()],
            vec!["input:b".to_string()],
            [9u8; 32],
        );
        let encoded = encode_ingress_request_v2(&request).unwrap();
        assert!(encoded.starts_with(INGRESS_REQUEST_V2_MAGIC));

        match decode_ingress_frame(&encoded, 4096).unwrap() {
            IngressFrame::V2(decoded) => assert_eq!(decoded, request),
            other => panic!("expected v2 frame, got {other:?}"),
        }
    }

    #[test]
    fn ingress_request_v1_still_round_trips_after_v2_addition() {
        let request = IngressRequestV1::new(packet(), vec!["ref:a".to_string()], vec![]);
        let encoded = encode_ingress_request_v1(&request).unwrap();
        match decode_ingress_frame(&encoded, 4096).unwrap() {
            IngressFrame::V1(decoded) => assert_eq!(decoded, request),
            other => panic!("expected v1 frame, got {other:?}"),
        }
    }
}
