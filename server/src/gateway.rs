use crate::ledger::Ledger;
use crate::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptEventKind};
use crate::verifier::{SignedVerifiedCallContext, VerificationError};
use async_trait::async_trait;
use libsec_core::ZenithPacket;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const PROTOTYPE_RECEIPT_SIGNER_KEY_ID: &str = "verifier:local-prototype";
const PROTOTYPE_RECEIPT_SIGNING_KEY: [u8; 32] = [7u8; 32];

#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, payload: &[u8]);
}

pub struct ConfigurableRouter {
    programs: HashMap<u8, Box<dyn MachineProgram>>,
    pool: SqlitePool,
    ledger: Ledger,
}

impl ConfigurableRouter {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            programs: HashMap::new(),
            ledger: Ledger::new(pool.clone()),
            pool,
        }
    }

    pub fn register(&mut self, opcode: u8, program: Box<dyn MachineProgram>) {
        self.programs.insert(opcode, program);
    }

    pub async fn route(&self, opcode: u8, payload: Vec<u8>) {
        let payload_size = payload.len() as i64;
        let timestamp = current_unix_seconds();

        if let Err(e) = sqlx::query(
            "INSERT INTO node_telemetry (opcode, payload_size, operation) VALUES (?, ?, ?)",
        )
        .bind(i64::from(opcode))
        .bind(payload_size)
        .bind("unverified.prototype")
        .execute(&self.pool)
        .await
        {
            eprintln!("secS [Telemetry]: failed to write log - {}", e);
        }
        if let Err(e) = self
            .ledger
            .record_event(
                ReceiptEventKind::PacketReceived,
                None,
                Some(opcode),
                Some("unverified.prototype"),
                None,
                Some(&format!("payload_size:{payload_size}")),
                timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write unverified event - {}", e);
        }

        match self.programs.get(&opcode) {
            Some(program) => program.execute(&payload).await,
            None => eprintln!("secS [Router]: rejected unmapped opcode {:#04x}", opcode),
        }
    }

    pub async fn record_reject(&self, packet: &ZenithPacket, error: VerificationError) {
        let timestamp = current_unix_seconds();
        let receipt = Receipt::reject_from_packet(
            format!("receipt-reject-{timestamp}-{:02x}", packet.opcode),
            packet,
            error,
            timestamp,
        );
        if let Err(e) = self.ledger.record_receipt(&receipt).await {
            eprintln!("secS [Ledger]: failed to write reject receipt - {}", e);
        }
        if let Err(e) = self
            .ledger
            .record_event(
                ReceiptEventKind::PacketRejected,
                Some(receipt.packet_hash),
                Some(packet.opcode),
                None,
                None,
                receipt.reason.as_deref(),
                timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write reject event - {}", e);
        }
    }

    pub async fn route_verified(&self, signed: &SignedVerifiedCallContext, payload: Vec<u8>) {
        let context = &signed.context;
        let payload_size = payload.len() as i64;
        let timestamp = current_unix_seconds();

        if let Err(e) = sqlx::query(
            "INSERT INTO node_telemetry (opcode, payload_size, operation) VALUES (?, ?, ?)",
        )
        .bind(i64::from(context.opcode))
        .bind(payload_size)
        .bind(&context.operation)
        .execute(&self.pool)
        .await
        {
            eprintln!("secS [Telemetry]: failed to write verified log - {}", e);
        }

        self.record_verify_receipt(signed, timestamp).await;
        self.record_operation_event(ReceiptEventKind::OperationRouted, signed, timestamp, None)
            .await;

        match self.programs.get(&context.opcode) {
            Some(program) => {
                self.record_operation_event(
                    ReceiptEventKind::HandlerStarted,
                    signed,
                    timestamp,
                    Some(&format!("payload_size:{payload_size}")),
                )
                .await;
                program.execute(&payload).await;
                self.record_execution_receipt(signed, Decision::Accepted, None, timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::HandlerSucceeded,
                    signed,
                    timestamp,
                    None,
                )
                .await;
            }
            None => {
                let reason = "handler_unavailable";
                self.record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::HandlerFailed,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
                eprintln!(
                    "secS [Router]: rejected verified operation without handler {} ({:#04x})",
                    context.operation, context.opcode
                );
            }
        }
    }

    async fn record_verify_receipt(&self, signed: &SignedVerifiedCallContext, timestamp: u64) {
        let receipt = Receipt::verify_from_signed_context(
            format!("receipt-verify-{timestamp}-{:02x}", signed.context.opcode),
            signed,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
        self.record_operation_event(ReceiptEventKind::PacketVerified, signed, timestamp, None)
            .await;
    }

    async fn record_execution_receipt(
        &self,
        signed: &SignedVerifiedCallContext,
        decision: Decision,
        reason: Option<&str>,
        timestamp: u64,
    ) {
        let receipt = Receipt::execution(
            format!("receipt-execute-{timestamp}-{:02x}", signed.context.opcode),
            &signed.context,
            decision,
            reason,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
    }

    async fn record_signed_receipt(&self, receipt: Receipt) {
        let signed = match receipt.sign_ed25519(
            PROTOTYPE_RECEIPT_SIGNER_KEY_ID,
            &PROTOTYPE_RECEIPT_SIGNING_KEY,
            AuthenticatorKind::Ed25519Verifier,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                eprintln!(
                    "secS [Ledger]: failed to sign receipt - {}",
                    error.reason_code()
                );
                return;
            }
        };
        if let Err(e) = self.ledger.record_receipt(&signed).await {
            eprintln!("secS [Ledger]: failed to write receipt - {}", e);
            return;
        }
        if let Err(e) = self
            .ledger
            .record_event(
                ReceiptEventKind::ReceiptEmitted,
                Some(signed.packet_hash),
                Some(signed.opcode),
                signed.operation.as_deref(),
                signed.handler_id.as_deref(),
                Some(signed.kind.as_str()),
                signed.timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write receipt event - {}", e);
        }
    }

    async fn record_operation_event(
        &self,
        event_kind: ReceiptEventKind,
        signed: &SignedVerifiedCallContext,
        timestamp: u64,
        reason: Option<&str>,
    ) {
        let context = &signed.context;
        if let Err(e) = self
            .ledger
            .record_event(
                event_kind,
                Some(context.packet_hash),
                Some(context.opcode),
                Some(&context.operation),
                context.handler_id.as_deref(),
                reason,
                timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write operation event - {}", e);
        }
    }
}
pub async fn init_telemetry_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS node_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            opcode INTEGER NOT NULL,
            payload_size INTEGER NOT NULL,
            operation TEXT NOT NULL DEFAULT 'unverified.prototype'
        );",
    )
    .execute(pool)
    .await?;

    Ledger::new(pool.clone()).init_schema().await
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub struct SubprocessForwarder {
    pub program: String,
    pub args: Vec<String>,
}

impl SubprocessForwarder {
    pub fn new(program: &str, args: Vec<&str>) -> Self {
        Self {
            program: program.to_string(),
            args: args.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[async_trait]
impl MachineProgram for SubprocessForwarder {
    async fn execute(&self, payload: &[u8]) {
        println!(
            "secS [Subprocess]: invoking `{} {:?}`",
            self.program, self.args
        );
        let mut child = match tokio::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("secS [Subprocess]: failed to spawn - {}", e);
                return;
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut stdin, payload).await {
                eprintln!(
                    "secS [Subprocess]: failed to write payload to stdin - {}",
                    e
                );
            }
        }
        let _ = child.wait().await;
    }
}

pub struct LocalRustQueue;

#[async_trait]
impl MachineProgram for LocalRustQueue {
    async fn execute(&self, payload: &[u8]) {
        println!("secS [Native Rust]: enqueueing {} bytes...", payload.len());
    }
}

pub fn register_prototype_bindings(router: &mut ConfigurableRouter) {
    router.register(
        0x10,
        Box::new(SubprocessForwarder::new(
            "bash",
            vec!["-c", "echo 'Bash received payload:'; cat"],
        )),
    );
    router.register(0x20, Box::new(LocalRustQueue));
    router.register(0x30, Box::new(SubprocessForwarder::new("jq", vec!["."])));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprocess_forwarder_new_copies_program_and_args() {
        let forwarder = SubprocessForwarder::new("bash", vec!["-c", "cat"]);

        assert_eq!(forwarder.program, "bash");
        assert_eq!(forwarder.args, vec!["-c".to_string(), "cat".to_string()]);
    }
}
