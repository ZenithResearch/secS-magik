use libsec_core::ZenithPacket;
use server::gateway::{init_telemetry_schema, ConfigurableRouter};
use server::ingress::{
    handle_gateway_connection_with_limits, read_bounded_wire_packet, IngressReadError,
};
use server::runtime_mode::RuntimeMode;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tokio::io::duplex;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
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

fn packet_prefix_with_declared_proof_len(proof_len: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[1u8; 16]);
    bytes.extend_from_slice(&[2u8; 12]);
    bytes.push(0x10);
    bytes.extend_from_slice(&proof_len.to_le_bytes());
    bytes
}

fn packet_prefix_with_declared_payload_len(payload_len: u64) -> Vec<u8> {
    let mut bytes = packet_prefix_with_declared_proof_len(1);
    bytes.push(1);
    bytes.extend_from_slice(&300u64.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes
}

#[tokio::test]
async fn ingress_decode_rejects_huge_declared_proof_vec_length_with_size_limit() {
    let reader = std::io::Cursor::new(packet_prefix_with_declared_proof_len(u64::MAX));

    let result = read_bounded_wire_packet(reader, 128, Duration::from_secs(1)).await;

    let Err(IngressReadError::LogicalFrameTooLarge {
        field,
        declared_len,
        limit,
    }) = result
    else {
        panic!("huge declared proof length should be a bounded logical-frame error");
    };
    assert_eq!(field, "proof");
    assert_eq!(declared_len, u64::MAX);
    assert_eq!(limit, 128);
}

#[tokio::test]
async fn ingress_decode_rejects_huge_declared_payload_vec_length_with_size_limit() {
    let reader = std::io::Cursor::new(packet_prefix_with_declared_payload_len(u64::MAX));

    let result = read_bounded_wire_packet(reader, 128, Duration::from_secs(1)).await;

    let Err(IngressReadError::LogicalFrameTooLarge {
        field,
        declared_len,
        limit,
    }) = result
    else {
        panic!("huge declared payload length should be a bounded logical-frame error");
    };
    assert_eq!(field, "encrypted_payload");
    assert_eq!(declared_len, u64::MAX);
    assert_eq!(limit, 128);
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

#[tokio::test]
async fn connection_uses_validated_runtime_mode_not_environment_for_plaintext_payload() {
    std::env::set_var("SECS_RUNTIME_MODE", "production_verified");
    std::env::set_var("SECZ_RUNTIME_MODE", "production_verified");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let router = Arc::new(ConfigurableRouter::new(pool));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let packet_bytes = bincode::serialize(&packet(b"plain local fixture payload")).unwrap();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        handle_gateway_connection_with_limits(
            router,
            socket,
            DEFAULT_TEST_WIRE_LIMIT,
            Duration::from_secs(1),
            RuntimeMode::LocalDevPlaintext,
        )
        .await;
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&packet_bytes).await.unwrap();
    client.shutdown().await.unwrap();
    server.await.unwrap();

    std::env::remove_var("SECS_RUNTIME_MODE");
    std::env::remove_var("SECZ_RUNTIME_MODE");
}

const DEFAULT_TEST_WIRE_LIMIT: usize = 2 * 1024 * 1024;
