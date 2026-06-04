use libsec_core::ZenithPacket;
use server::ingress::{read_bounded_wire_packet, IngressReadError};
use tokio::io::duplex;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};

fn packet(payload: &[u8]) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: payload.to_vec(),
        mac: [0u8; 16],
    }
}

#[tokio::test]
async fn ingress_source_bounds_wire_reads_before_deserialization() {
    let (mut client, server) = duplex(16);
    let oversized = vec![0xAA; 65];

    let writer = tokio::spawn(async move {
        client.write_all(&oversized).await.unwrap();
    });

    let result = read_bounded_wire_packet(server, 64, Duration::from_secs(1)).await;
    writer.await.unwrap();

    assert!(matches!(
        result,
        Err(IngressReadError::WireFrameTooLarge { limit: 64 })
    ));
}

#[tokio::test]
async fn oversized_wire_frame_rejects_before_packet_decode() {
    let bytes = bincode::serialize(&packet(&vec![0u8; 256])).unwrap();
    assert!(bytes.len() > 64);
    let reader = std::io::Cursor::new(bytes);

    let result = read_bounded_wire_packet(reader, 64, Duration::from_secs(1)).await;

    assert!(matches!(
        result,
        Err(IngressReadError::WireFrameTooLarge { limit: 64 })
    ));
}

#[tokio::test]
async fn malformed_under_limit_packet_stays_malformed_not_over_limit() {
    let reader = std::io::Cursor::new(vec![1, 2, 3, 4]);

    let result = read_bounded_wire_packet(reader, 64, Duration::from_secs(1)).await;

    assert!(matches!(result, Err(IngressReadError::MalformedPacket(_))));
}

#[tokio::test]
async fn empty_ingress_stream_exits_quietly() {
    let reader = std::io::Cursor::new(Vec::<u8>::new());

    let result = read_bounded_wire_packet(reader, 64, Duration::from_secs(1)).await;

    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn valid_max_size_frame_accepts() {
    let mut payload_len = 0usize;
    let max_wire_bytes = loop {
        let bytes = bincode::serialize(&packet(&vec![0u8; payload_len])).unwrap();
        let next = bincode::serialize(&packet(&vec![0u8; payload_len + 1])).unwrap();
        if next.len() > bytes.len() {
            break bytes.len();
        }
        payload_len += 1;
    };
    let bytes = bincode::serialize(&packet(&vec![0u8; payload_len])).unwrap();
    assert_eq!(bytes.len(), max_wire_bytes);
    let reader = std::io::Cursor::new(bytes);

    let result = read_bounded_wire_packet(reader, max_wire_bytes, Duration::from_secs(1))
        .await
        .unwrap();

    assert!(result.is_some());
}

#[tokio::test]
async fn slow_incomplete_ingress_stream_times_out() {
    let (_client, server) = duplex(8);

    let result = timeout(
        Duration::from_secs(1),
        read_bounded_wire_packet(server, 64, Duration::from_millis(25)),
    )
    .await
    .expect("read helper should return after its own deadline");

    assert!(matches!(result, Err(IngressReadError::ReadTimeout)));
}
