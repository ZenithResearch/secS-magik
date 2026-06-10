use libsec_core::ZenithPacket;
use server::gateway::{init_telemetry_schema, ConfigurableRouter};
use server::ingress::{
    handle_gateway_connection_with_limits, read_bounded_wire_packet, IngressReadError,
};
use server::ledger::Ledger;
use server::runtime_mode::RuntimeMode;
use server::verifier::VerificationError;
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
async fn valid_packet_with_trailing_bytes_rejects_as_malformed() {
    let mut bytes = bincode::serialize(&packet(b"payload")).unwrap();
    bytes.extend_from_slice(b"trailing-smuggled-bytes");
    let reader = std::io::Cursor::new(bytes);

    let result = read_bounded_wire_packet(reader, 1024, Duration::from_secs(1)).await;

    assert!(
        matches!(result, Err(IngressReadError::MalformedPacket(_))),
        "ingress must reject valid packet prefixes with extra trailing bytes so packet hashes/receipts cannot ignore transport bytes"
    );
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

type RejectReceiptRow = (String, String, String, Vec<u8>, Vec<u8>, i64);

#[tokio::test]
async fn ingress_pre_decode_reject_audit() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let router = Arc::new(ConfigurableRouter::new(pool.clone()));

    for _ in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router.clone();
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
        client.write_all(b"not a zenith packet").await.unwrap();
        client.shutdown().await.unwrap();
        server.await.unwrap();
    }

    let reason = VerificationError::MalformedPacket.reason_code();
    let receipts: Vec<RejectReceiptRow> = sqlx::query_as(
        "SELECT receipt_id, kind, reason, session_id, nonce, opcode FROM receipts WHERE kind = 'reject' ORDER BY receipt_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[0].0, receipts[1].0);
    assert_ne!(receipts[0].4, receipts[1].4);
    for receipt in &receipts {
        assert_eq!(receipt.1, "reject");
        assert_eq!(receipt.2, reason);
        assert_eq!(receipt.3, [0u8; 16].to_vec());
        assert_eq!(receipt.5, 0);
        assert!(receipt.0.starts_with("receipt-reject-"));
        assert!(!receipt.0.contains("not a zenith packet"));
    }

    let rejected_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'packet_rejected' AND reason = ?",
    )
    .bind(reason)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rejected_event_count.0, 2);

    let emitted_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'receipt_emitted' AND reason = 'reject'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(emitted_event_count.0, 2);

    for receipt in &receipts {
        let inspection = Ledger::new(pool.clone())
            .inspect_receipt_by_id(&receipt.0)
            .await
            .unwrap()
            .expect("pre-decode reject receipt should be inspectable by id");
        assert_eq!(inspection.kind.as_str(), "reject");
        assert_eq!(inspection.decision.as_str(), "rejected");
        assert_eq!(inspection.reason.as_deref(), Some(reason));
        assert_eq!(
            inspection.redaction_policy,
            "local_redacted_no_payload_or_private_evidence_by_default"
        );
    }

    let leaked_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE reason LIKE '%not a zenith packet%' OR operation LIKE '%not a zenith packet%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leaked_count.0, 0);
}

const DEFAULT_TEST_WIRE_LIMIT: usize = 2 * 1024 * 1024;

#[tokio::test]
#[serial_test::serial]
async fn spliced_tunnel_ciphertext_rejects_and_creates_no_second_replay_reservation() {
    // M12.4: a captured (nonce, ciphertext) pair re-bound to a different
    // session_id has a fresh replay key, so without AEAD associated data the
    // payload decrypts and executes again. With AAD binding the splice must be
    // rejected as bad_mac before routing, with no second replay reservation.
    std::env::set_var(
        "SECS_TUNNEL_KEY_HEX",
        "0101010101010101010101010101010101010101010101010101010101010101",
    );
    std::env::remove_var("SECZ_TUNNEL_KEY_HEX");

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let router = Arc::new(ConfigurableRouter::new(pool.clone()));

    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let ciphertext = libsec_core::tunnel::encrypt_payload(
        &key,
        &nonce,
        b"tunnel payload",
        &libsec_core::tunnel::packet_aad(&[0xAA; 16], 0x10, 300),
    );

    let legit = ZenithPacket {
        session_id: [0xAA; 16],
        nonce,
        opcode: 0x10,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: ciphertext.clone(),
        mac: [0u8; 16],
    };
    let spliced = ZenithPacket {
        session_id: [0xBB; 16],
        ..legit.clone()
    };

    for packet in [&legit, &spliced] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_gateway_connection_with_limits(
                router,
                socket,
                DEFAULT_TEST_WIRE_LIMIT,
                Duration::from_secs(1),
                RuntimeMode::LocalDevTunnel,
            )
            .await;
        });
        let bytes = bincode::serialize(packet).unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        server.await.unwrap();
    }

    let reservations: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        reservations.0, 1,
        "spliced packet must not create a second replay reservation"
    );

    let bad_mac_rejects: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM receipts WHERE kind = 'reject' AND reason = ?")
            .bind(VerificationError::BadMac.reason_code())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        bad_mac_rejects.0, 1,
        "splice must surface as the existing bad_mac/undecryptable reject"
    );

    std::env::remove_var("SECS_TUNNEL_KEY_HEX");
}

#[tokio::test]
async fn caller_auth_rejects_emit_inspectable_receipts_without_replay_reservation() {
    use ed25519_dalek::SigningKey;
    use libsec_core::caller_proof::{
        caller_canonical_bytes, encode_caller_proof, CALLER_SIGNATURE_LEN,
    };
    use server::caller::{CallerKey, CallerKeyRegistry};

    fn caller_packet(signer: &SigningKey, key_id: &str, session_id: [u8; 16]) -> ZenithPacket {
        let nonce = [0xBB; 12];
        let opcode = 0x10;
        let claim_ttl = 300;
        let payload = b"caller audit payload".to_vec();
        let canonical = caller_canonical_bytes(&session_id, &nonce, opcode, claim_ttl, &payload);
        let signature_bytes = libsec_core::zk::generate_proof(signer, &canonical);
        let mut signature = [0u8; CALLER_SIGNATURE_LEN];
        signature.copy_from_slice(&signature_bytes);
        ZenithPacket {
            session_id,
            nonce,
            opcode,
            proof: encode_caller_proof(key_id, &signature),
            claim_ttl,
            encrypted_payload: payload,
            mac: [0u8; 16],
        }
    }

    let registered = SigningKey::from_bytes(&[1u8; 32]);
    let impostor = SigningKey::from_bytes(&[2u8; 32]);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let mut router = ConfigurableRouter::new(pool.clone());
    router.set_caller_registry(CallerKeyRegistry::from_keys([CallerKey::active(
        "caller:audit",
        "did:example:audit",
        registered.verifying_key(),
    )]));
    let router = Arc::new(router);

    // Forged proof first (impostor signs while claiming the registered id),
    // then a valid call from the registered caller.
    let forged = caller_packet(&impostor, "caller:audit", [0xA1; 16]);
    let valid = caller_packet(&registered, "caller:audit", [0xA2; 16]);

    for packet in [&forged, &valid] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router.clone();
        let server_task = tokio::spawn(async move {
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
        let bytes = bincode::serialize(packet).unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    // The caller-auth reject left an inspectable reject receipt...
    let rejects: Vec<(String, String)> =
        sqlx::query_as("SELECT receipt_id, reason FROM receipts WHERE kind = 'reject'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rejects.len(), 1, "exactly one caller-auth reject expected");
    assert_eq!(
        rejects[0].1,
        VerificationError::BadCallerProof.reason_code()
    );
    let inspection = Ledger::new(pool.clone())
        .inspect_receipt_by_id(&rejects[0].0)
        .await
        .unwrap()
        .expect("caller-auth reject receipt must be inspectable by id");
    assert_eq!(inspection.decision.as_str(), "rejected");
    assert_eq!(
        inspection.reason.as_deref(),
        Some(VerificationError::BadCallerProof.reason_code())
    );

    // ...and created no replay reservation; only the valid call reserved.
    let reservations: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT session_id FROM replay_reservations")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        reservations.len(),
        1,
        "caller-auth rejects must not create replay reservations"
    );
    assert_eq!(reservations[0].0, [0xA2; 16].to_vec());
}
