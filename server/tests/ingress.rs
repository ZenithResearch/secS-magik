use libsec_core::ingress_request::{encode_ingress_request_v1, IngressRequestV1};
use libsec_core::ZenithPacket;
use server::config::GatewayRuntimeConfig;
use server::dregg_authority::{
    DreggAuthorityEntry, DreggAuthorityFinalityMode, DreggAuthorityRegistry,
    DreggAuthorityRevocationStatus, DreggAuthorityRevocationVerifierMode, DreggAuthorityStatus,
    DreggAuthorityStatusPolicy,
};
use server::evidence::{
    DreggAuthorityEvidenceAdapter, DreggAuthorityGrantFixture, EvidenceAdapter, EvidenceKind,
    EvidenceRequest, EvidenceResult, EvidenceSummary,
};
use server::gateway::{init_telemetry_schema, register_runtime_bindings, ConfigurableRouter};
use server::ingress::{
    handle_gateway_connection_with_limits, install_configured_permission_policy,
    read_bounded_ingress_request, read_bounded_wire_packet, IngressReadError,
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

fn write_valid_permission_policy(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"[
          {
            "caller_id": "did:example:test",
            "opcode": 16,
            "operation": "file.write",
            "resource": { "kind": "prefix", "prefix": "urn:secs:demo:" },
            "effect": "allow",
            "status": "active",
            "authority_source": "receiver_local",
            "not_before": 0,
            "not_after": 4102444800
          }
        ]"#,
    )
    .expect("permission policy fixture should be writable");
    path
}

#[tokio::test]
async fn configured_permission_policy_is_installed_before_serving() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut router = ConfigurableRouter::new(pool);
    let permission_policy_path = write_valid_permission_policy("configured-policy-install");
    let mut config = GatewayRuntimeConfig::local_fixture();
    config.permission_policy_path = Some(permission_policy_path.clone());

    install_configured_permission_policy(&mut router, &config);

    let _ = std::fs::remove_file(permission_policy_path);
    assert!(
        router.has_permission_policy(),
        "canonical ingress startup must install configured permission policy before serving"
    );
}

#[tokio::test]
async fn bounded_ingress_request_decodes_live_evidence_refs_and_public_inputs() {
    let request = IngressRequestV1::new(
        packet(b"payload"),
        vec![
            "wallet-ref".to_string(),
            "credential-ref".to_string(),
            "wallet-ref".to_string(),
        ],
        vec!["origin:https://example.test".to_string()],
    );
    let bytes = encode_ingress_request_v1(&request).unwrap();

    let frame =
        read_bounded_ingress_request(std::io::Cursor::new(bytes), 4096, Duration::from_secs(1))
            .await
            .unwrap()
            .expect("request should decode");

    assert_eq!(frame.packet.opcode, 0x10);
    assert_eq!(
        frame.evidence_inputs.evidence_refs(),
        &["wallet-ref".to_string(), "credential-ref".to_string()]
    );
    assert_eq!(
        frame.evidence_inputs.public_inputs(),
        &["origin:https://example.test".to_string()]
    );
}

#[tokio::test]
async fn bounded_ingress_request_rejects_oversized_evidence_metadata() {
    let mut bytes = libsec_core::ingress_request::INGRESS_REQUEST_V1_MAGIC.to_vec();
    bytes.extend_from_slice(&(u64::MAX).to_le_bytes());

    let result =
        read_bounded_ingress_request(std::io::Cursor::new(bytes), 4096, Duration::from_secs(1))
            .await;

    assert!(matches!(
        result,
        Err(IngressReadError::LogicalFrameTooLarge {
            field: "ingress_request",
            ..
        })
    ));
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
#[serial_test::serial]
async fn caller_auth_rejects_emit_inspectable_receipts_without_replay_reservation() {
    std::env::remove_var("SECS_TUNNEL_KEY_HEX");
    std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
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

mod decision_response {
    use super::*;
    use libsec_core::response::{DecisionResponse, MAX_DECISION_RESPONSE_BYTES};
    use tokio::io::AsyncReadExt;

    async fn call_gateway_with_runtime(
        router: Arc<ConfigurableRouter>,
        packet_bytes: Vec<u8>,
        runtime_mode: RuntimeMode,
    ) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_gateway_connection_with_limits(
                router,
                socket,
                DEFAULT_TEST_WIRE_LIMIT,
                Duration::from_secs(1),
                runtime_mode,
            )
            .await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&packet_bytes).await.unwrap();
        client.shutdown().await.unwrap();

        let mut frame = Vec::new();
        timeout(
            Duration::from_secs(2),
            client
                .take((MAX_DECISION_RESPONSE_BYTES + 1) as u64)
                .read_to_end(&mut frame),
        )
        .await
        .expect("reading the decision response must not hang")
        .expect("decision response read should succeed");
        server_task.await.unwrap();
        frame
    }

    async fn call_gateway(router: Arc<ConfigurableRouter>, packet_bytes: Vec<u8>) -> Vec<u8> {
        call_gateway_with_runtime(router, packet_bytes, RuntimeMode::LocalDevPlaintext).await
    }

    #[derive(Default)]
    struct RecordingEvidenceAdapter(std::sync::Mutex<Vec<EvidenceRequest>>);

    #[derive(Default)]
    struct RejectingAttenuationEvidenceAdapter(std::sync::Mutex<Vec<EvidenceRequest>>);

    impl EvidenceAdapter for RejectingAttenuationEvidenceAdapter {
        fn kind(&self) -> EvidenceKind {
            EvidenceKind::DreggAuthority
        }

        fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
            self.0.lock().unwrap().push(request.clone());
            if request
                .public_inputs
                .iter()
                .any(|input| input == "requested_resource:urn:secs:member:bob/profile")
            {
                return EvidenceResult::Rejected(VerificationError::AuthorityAmplification);
            }
            EvidenceResult::Satisfied(EvidenceSummary {
                kind: EvidenceKind::DreggAuthority,
                subject: request.subject.clone(),
                audience: request.audience.clone(),
                operation: request.operation.clone(),
                resource: request.resource.clone(),
                local_dev_test_only: false,
                public_proof: false,
                summary_fields: vec!["attenuation:non_amplifying".to_string()],
            })
        }
    }

    impl EvidenceAdapter for RecordingEvidenceAdapter {
        fn kind(&self) -> EvidenceKind {
            EvidenceKind::DreggAuthority
        }

        fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
            self.0.lock().unwrap().push(request.clone());
            if !request
                .evidence_refs
                .contains(&"wallet-live-ref".to_string())
                || !request
                    .evidence_refs
                    .contains(&"credential-live-ref".to_string())
                || !request
                    .evidence_refs
                    .contains(&"dregg-live-ref".to_string())
            {
                return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
            }
            EvidenceResult::Satisfied(EvidenceSummary {
                kind: EvidenceKind::DreggAuthority,
                subject: request.subject.clone(),
                audience: request.audience.clone(),
                operation: request.operation.clone(),
                resource: request.resource.clone(),
                local_dev_test_only: false,
                public_proof: false,
                summary_fields: vec![
                    "authority_class:dregg_authority".to_string(),
                    "tier:m15_production_shaped".to_string(),
                    "token:dga1_[redacted]".to_string(),
                ],
            })
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn versioned_live_ingress_request_supplies_evidence_refs_to_verifier() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let adapter = Arc::new(RecordingEvidenceAdapter::default());
        let mut router = ConfigurableRouter::new(pool);
        register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
        router.set_evidence_adapter(adapter.clone());
        let router = Arc::new(router);

        let mut request_packet = packet(br#"{"membership":"requested"}"#);
        request_packet.opcode = 0x44;
        let request = IngressRequestV1::new(
            request_packet,
            vec![
                "wallet-live-ref".to_string(),
                "credential-live-ref".to_string(),
                "dregg-live-ref".to_string(),
                "wallet-live-ref".to_string(),
            ],
            vec!["origin:https://example.test".to_string()],
        );
        let frame = call_gateway(router, encode_ingress_request_v1(&request).unwrap()).await;

        let response = DecisionResponse::decode(&frame)
            .expect("versioned ingress call must answer with a decision response");
        assert!(
            response.is_accepted(),
            "live evidence-backed request should accept"
        );
        let seen = adapter.0.lock().unwrap();
        assert_eq!(
            seen.len(),
            1,
            "the live request must invoke the evidence adapter exactly once"
        );
        assert_eq!(
            seen[0].evidence_refs,
            vec!["wallet-live-ref", "credential-live-ref", "dregg-live-ref"],
            "ingress must dedupe refs and pass them to canonical EvidenceRequest"
        );
        assert!(
            seen[0]
                .public_inputs
                .contains(&"origin:https://example.test".to_string()),
            "ingress must preserve caller public inputs alongside descriptor inputs"
        );
        assert_eq!(seen[0].operation, "membership.provision");
    }

    fn dregg_registry_for_attenuation() -> DreggAuthorityRegistry {
        DreggAuthorityRegistry::new([DreggAuthorityEntry {
            issuer_id: "did:dregg:issuer:fixture".to_string(),
            issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
            issuer_public_key_hex:
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            federation_id: "dregg-federation:fixture".to_string(),
            root_ref: "dregg-root:fixture-root-2026q2".to_string(),
            root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
            epoch_id: "epoch:2026q2".to_string(),
            epoch_not_before: 1_770_000_000,
            epoch_not_after: 1_777_776_000,
            accepted_audiences: vec!["secS://receiver-a".to_string()],
            accepted_operations: vec!["membership.provision".to_string()],
            accepted_resources: vec!["application/json".to_string()],
            accepted_suites: vec!["dregg_authority_fixture_v1".to_string()],
            status_policy: DreggAuthorityStatusPolicy {
                require_status: true,
                max_status_age_seconds: 300,
                require_revocation_check: true,
                require_finality: false,
                revocation_verifier_mode: DreggAuthorityRevocationVerifierMode::ExpectedRootBinding,
                finality_mode: DreggAuthorityFinalityMode::FixtureStatusOnly,
                expected_revocation_root_ref: Some(
                    "dregg-revocation-root:fixture-2026q2".to_string(),
                ),
            },
            root_status: DreggAuthorityStatus::Active,
            issuer_status: DreggAuthorityStatus::Active,
        }])
        .unwrap()
    }

    fn attenuated_dregg_adapter() -> DreggAuthorityEvidenceAdapter {
        DreggAuthorityEvidenceAdapter::new(
            [DreggAuthorityGrantFixture {
                evidence_ref: "dregg-live-ref".to_string(),
                token: DreggAuthorityGrantFixture::fixture_token_with_resource_prefix(
                    "prototype.local-dev.subject",
                    "membership.provision",
                    "urn:secs:member:alice/",
                    1_777_000_000,
                ),
                issuer_id: "did:dregg:issuer:fixture".to_string(),
                issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
                root_ref: "dregg-root:fixture-root-2026q2".to_string(),
                root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
                epoch_id: "epoch:2026q2".to_string(),
                suite: "dregg_authority_fixture_v1".to_string(),
                status_checked_at: Some(1_770_000_200),
                revocation_status: Some(DreggAuthorityRevocationStatus::Active),
                finality_status: None,
                attested_revocation_root_ref: Some(
                    "dregg-revocation-root:fixture-2026q2".to_string(),
                ),
            }],
            dregg_registry_for_attenuation(),
            1_770_000_300,
        )
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn amplified_live_ingress_authority_rejects_before_handler_dispatch() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let adapter = Arc::new(RejectingAttenuationEvidenceAdapter::default());
        let mut router = ConfigurableRouter::new(pool.clone());
        register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
        router.set_evidence_adapter(adapter.clone());
        let router = Arc::new(router);

        let mut request_packet = packet(br#"{"membership":"requested"}"#);
        request_packet.opcode = 0x44;
        let request = IngressRequestV1::new(
            request_packet,
            vec!["dregg-live-ref".to_string()],
            vec![
                "origin:https://example.test".to_string(),
                "requested_resource:urn:secs:member:bob/profile".to_string(),
            ],
        );
        let frame = call_gateway(router, encode_ingress_request_v1(&request).unwrap()).await;

        let response = DecisionResponse::decode(&frame)
            .expect("amplified live ingress call must answer with a decision response");
        assert!(!response.is_accepted());
        assert_eq!(
            response.reason_code.as_deref(),
            Some(VerificationError::AuthorityAmplification.reason_code()),
            "live ingress must preserve the attenuation failure reason before dispatch"
        );
        assert_eq!(
            adapter.0.lock().unwrap().len(),
            1,
            "the live path should reject from evidence verification, before handler dispatch"
        );
        let accepts: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM receipts WHERE kind = 'accept'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            accepts.0, 0,
            "amplified authority must not create an accept receipt"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn real_dregg_attenuation_adapter_accepts_trusted_decrypted_tunnel_payload_resource() {
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
        let mut router = ConfigurableRouter::new(pool.clone());
        register_runtime_bindings(&mut router, RuntimeMode::LocalDevTunnel);
        router.set_evidence_adapter(Arc::new(attenuated_dregg_adapter()));
        let router = Arc::new(router);

        let mut request_packet = packet(b"");
        request_packet.opcode = 0x44;
        request_packet.nonce = [7u8; 12];
        request_packet.encrypted_payload = libsec_core::tunnel::encrypt_payload(
            &[1u8; 32],
            &request_packet.nonce,
            br#"{"membership":"requested","requested_resource":"urn:secs:member:alice/profile"}"#,
            &libsec_core::tunnel::packet_aad(
                &request_packet.session_id,
                request_packet.opcode,
                request_packet.claim_ttl,
            ),
        );
        let request = IngressRequestV1::new(
            request_packet,
            vec!["dregg-live-ref".to_string()],
            vec!["origin:https://example.test".to_string()],
        );
        let frame = call_gateway_with_runtime(
            router,
            encode_ingress_request_v1(&request).unwrap(),
            RuntimeMode::LocalDevTunnel,
        )
        .await;

        let response = DecisionResponse::decode(&frame)
            .expect("trusted decrypted requested resource should produce a decision response");
        assert!(
            response.is_accepted(),
            "trusted requested resource must be derived from decrypted tunnel payload, not ciphertext"
        );
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn real_dregg_attenuation_adapter_accepts_trusted_payload_resource_without_public_input()
    {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let mut router = ConfigurableRouter::new(pool.clone());
        register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
        router.set_evidence_adapter(Arc::new(attenuated_dregg_adapter()));
        let router = Arc::new(router);

        let mut request_packet = packet(
            br#"{"membership":"requested","requested_resource":"urn:secs:member:alice/profile"}"#,
        );
        request_packet.opcode = 0x44;
        let request = IngressRequestV1::new(
            request_packet,
            vec!["dregg-live-ref".to_string()],
            vec!["origin:https://example.test".to_string()],
        );
        let frame = call_gateway(router, encode_ingress_request_v1(&request).unwrap()).await;

        let response = DecisionResponse::decode(&frame)
            .expect("trusted in-prefix requested resource should produce a decision response");
        assert!(
            response.is_accepted(),
            "trusted requested resource derived from payload should satisfy Dregg attenuation without caller public input"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn real_dregg_attenuation_adapter_rejects_amplified_live_ingress_before_dispatch() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let mut router = ConfigurableRouter::new(pool.clone());
        register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
        router.set_evidence_adapter(Arc::new(attenuated_dregg_adapter()));
        let router = Arc::new(router);

        let mut request_packet = packet(
            br#"{"membership":"requested","requested_resource":"urn:secs:member:bob/profile"}"#,
        );
        request_packet.opcode = 0x44;
        let request = IngressRequestV1::new(
            request_packet,
            vec!["dregg-live-ref".to_string()],
            vec!["requested_resource:urn:secs:member:alice/profile".to_string()],
        );
        let frame = call_gateway(router, encode_ingress_request_v1(&request).unwrap()).await;

        let response = DecisionResponse::decode(&frame)
            .expect("real Dregg adapter amplification reject must answer with a decision response");
        assert!(!response.is_accepted());
        assert_eq!(
            response.reason_code.as_deref(),
            Some(VerificationError::AuthorityAmplification.reason_code())
        );
        let accepts: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM receipts WHERE kind = 'accept'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            accepts.0, 0,
            "real Dregg attenuation failure must reject before accept/execute receipts"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn valid_call_receives_accept_decision_with_ledger_references() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let mut router = ConfigurableRouter::new(pool.clone());
        server::gateway::register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
        let router = Arc::new(router);

        let frame = call_gateway(
            router,
            bincode::serialize(&packet(b"decision accept")).unwrap(),
        )
        .await;

        assert!(
            !frame.is_empty(),
            "gateway must answer the caller with a decision frame"
        );
        assert!(frame.len() <= MAX_DECISION_RESPONSE_BYTES);
        let response = DecisionResponse::decode(&frame)
            .expect("response frame must decode as a versioned DecisionResponse");
        assert!(response.is_accepted());
        assert_eq!(response.reason_code, None);

        // The references must resolve in the operator ledger.
        let context_id = response.context_id.expect("accept must carry a context id");
        let receipt_id = response.receipt_id.expect("accept must carry a receipt id");
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT receipt_id FROM receipts WHERE context_id = ?")
                .bind(&context_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert!(
            rows.iter().any(|(id,)| id == &receipt_id),
            "the returned receipt id must be inspectable under the returned context id"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn rejected_call_receives_typed_reason_matching_persisted_receipt() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let router = Arc::new(ConfigurableRouter::new(pool.clone()));

        // Empty proof rejects at the envelope check with a typed reason.
        let mut bad = packet(b"decision reject");
        bad.proof = Vec::new();
        let frame = call_gateway(router, bincode::serialize(&bad).unwrap()).await;

        let response = DecisionResponse::decode(&frame)
            .expect("reject must still answer with a decision frame");
        assert!(!response.is_accepted());
        let reason = response
            .reason_code
            .expect("reject must carry a typed reason");
        assert_eq!(
            reason,
            VerificationError::MissingPrototypeProofEnvelope.reason_code()
        );

        let persisted: (String,) =
            sqlx::query_as("SELECT reason FROM receipts WHERE kind = 'reject' LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(persisted.0, reason);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn pre_decode_reject_still_answers_with_a_typed_reason() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let router = Arc::new(ConfigurableRouter::new(pool));

        let frame = call_gateway(router, b"not a zenith packet".to_vec()).await;

        let response = DecisionResponse::decode(&frame)
            .expect("pre-decode rejects must still answer with a decision frame");
        assert!(!response.is_accepted());
        assert_eq!(
            response.reason_code.as_deref(),
            Some(VerificationError::MalformedPacket.reason_code())
        );
        assert!(
            response.receipt_id.is_some(),
            "pre-decode rejects emit synthetic reject receipts and must reference them"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn non_reading_client_does_not_stall_the_gateway() {
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_telemetry_schema(&pool).await.unwrap();
        let router = Arc::new(ConfigurableRouter::new(pool));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
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
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&bincode::serialize(&packet(b"never reads")).unwrap())
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        // Drop without reading the response: the handler must still finish
        // within the bounded write window instead of stalling.
        drop(client);

        timeout(Duration::from_secs(3), server_task)
            .await
            .expect("gateway handler must not stall on a non-reading client")
            .unwrap();
    }
}
