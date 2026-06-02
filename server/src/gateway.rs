use crate::verifier::SignedVerifiedCallContext;
use async_trait::async_trait;
use sqlx::SqlitePool;
use std::collections::HashMap;

#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, payload: &[u8]);
}

pub struct ConfigurableRouter {
    programs: HashMap<u8, Box<dyn MachineProgram>>,
    pool: SqlitePool,
}

impl ConfigurableRouter {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            programs: HashMap::new(),
            pool,
        }
    }

    pub fn register(&mut self, opcode: u8, program: Box<dyn MachineProgram>) {
        self.programs.insert(opcode, program);
    }

    pub async fn route(&self, opcode: u8, payload: Vec<u8>) {
        let payload_size = payload.len() as i64;

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

        match self.programs.get(&opcode) {
            Some(program) => program.execute(&payload).await,
            None => eprintln!("secS [Router]: rejected unmapped opcode {:#04x}", opcode),
        }
    }

    pub async fn route_verified(&self, signed: &SignedVerifiedCallContext, payload: Vec<u8>) {
        let context = &signed.context;
        let payload_size = payload.len() as i64;

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

        match self.programs.get(&context.opcode) {
            Some(program) => program.execute(&payload).await,
            None => eprintln!(
                "secS [Router]: rejected verified operation without handler {} ({:#04x})",
                context.operation, context.opcode
            ),
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
    .await
    .map(|_| ())
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
