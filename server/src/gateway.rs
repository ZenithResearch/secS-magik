use crate::identity::{explicit_test_fixture_identity, NodeVerifierIdentity};
use crate::ledger::Ledger;
use crate::receipt::{Decision, Receipt, ReceiptEventKind};
use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use async_trait::async_trait;
use libsec_core::ZenithPacket;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

const PROTOTYPE_RECEIPT_SIGNING_KEY: [u8; 32] = [7u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerOutcome {
    pub decision: Decision,
    pub reason: Option<String>,
}

impl HandlerOutcome {
    pub fn succeeded() -> Self {
        Self {
            decision: Decision::Accepted,
            reason: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Rejected,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub max_payload_bytes: usize,
    pub handler_timeout: Duration,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 1024 * 1024,
            handler_timeout: Duration::from_secs(30),
        }
    }
}

#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, context: &VerifiedCallContext, payload: &[u8]) -> HandlerOutcome;
}

pub struct ConfigurableRouter {
    programs: HashMap<u8, Box<dyn MachineProgram>>,
    pool: SqlitePool,
    ledger: Ledger,
    limits: ExecutionLimits,
    identity: NodeVerifierIdentity,
}

impl ConfigurableRouter {
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_limits(pool, ExecutionLimits::default())
    }

    pub fn with_limits(pool: SqlitePool, limits: ExecutionLimits) -> Self {
        Self::with_limits_and_identity(
            pool,
            limits,
            explicit_test_fixture_identity(
                "verifier:local-prototype",
                PROTOTYPE_RECEIPT_SIGNING_KEY,
            ),
        )
    }

    pub fn with_identity(pool: SqlitePool, identity: NodeVerifierIdentity) -> Self {
        Self::with_limits_and_identity(pool, ExecutionLimits::default(), identity)
    }

    pub fn with_limits_and_identity(
        pool: SqlitePool,
        limits: ExecutionLimits,
        identity: NodeVerifierIdentity,
    ) -> Self {
        Self {
            programs: HashMap::new(),
            ledger: Ledger::new(pool.clone()),
            pool,
            limits,
            identity,
        }
    }

    pub fn register(&mut self, opcode: u8, program: Box<dyn MachineProgram>) {
        self.programs.insert(opcode, program);
    }

    pub fn identity(&self) -> &NodeVerifierIdentity {
        &self.identity
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
            Some(_) => eprintln!(
                "secS [Router]: rejected unverified handler route for opcode {:#04x}",
                opcode
            ),
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

        if payload.len() > self.limits.max_payload_bytes {
            let reason = "payload_too_large";
            self.record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                .await;
            self.record_operation_event(
                ReceiptEventKind::HandlerFailed,
                signed,
                timestamp,
                Some(reason),
            )
            .await;
            return;
        }

        match self.programs.get(&context.opcode) {
            Some(program) => {
                self.record_operation_event(
                    ReceiptEventKind::HandlerStarted,
                    signed,
                    timestamp,
                    Some(&format!("payload_size:{payload_size}")),
                )
                .await;
                let outcome = match timeout(
                    self.limits.handler_timeout,
                    program.execute(context, &payload),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => HandlerOutcome::rejected("handler_timeout"),
                };
                let reason = outcome.reason.as_deref();
                self.record_execution_receipt(signed, outcome.decision, reason, timestamp)
                    .await;
                let event_kind = match outcome.decision {
                    Decision::Accepted => ReceiptEventKind::HandlerSucceeded,
                    Decision::Rejected => ReceiptEventKind::HandlerFailed,
                };
                self.record_operation_event(event_kind, signed, timestamp, reason)
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
        let signed = match self.identity.sign_receipt(receipt) {
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
    async fn execute(&self, context: &VerifiedCallContext, payload: &[u8]) -> HandlerOutcome {
        let Some(handler_id) = context.handler_id.as_deref() else {
            return HandlerOutcome::rejected("handler_unavailable");
        };
        if !handler_id.starts_with("dev/") {
            return HandlerOutcome::rejected("handler_not_dev_bound");
        }
        println!(
            "secS [Subprocess]: invoking verified dev handler `{}` via `{} {:?}`",
            handler_id, self.program, self.args
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
                return HandlerOutcome::rejected("handler_spawn_failed");
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut stdin, payload).await {
                eprintln!(
                    "secS [Subprocess]: failed to write payload to stdin - {}",
                    e
                );
                return HandlerOutcome::rejected("handler_stdin_failed");
            }
        }
        match child.wait().await {
            Ok(status) if status.success() => HandlerOutcome::succeeded(),
            Ok(_) => HandlerOutcome::rejected("handler_exit_failed"),
            Err(_) => HandlerOutcome::rejected("handler_wait_failed"),
        }
    }
}

pub struct LocalRustQueue;

#[async_trait]
impl MachineProgram for LocalRustQueue {
    async fn execute(&self, context: &VerifiedCallContext, payload: &[u8]) -> HandlerOutcome {
        println!(
            "secS [Native Rust]: enqueueing {} bytes for handler {:?}...",
            payload.len(),
            context.handler_id
        );
        HandlerOutcome::succeeded()
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
