use crate::gateway::ExecutionLimits;
use crate::ingress::{DEFAULT_INGRESS_READ_TIMEOUT, DEFAULT_MAX_WIRE_BYTES};
use crate::ontology::DEFAULT_RECEIVER_AUDIENCE;
use crate::runtime_mode::RuntimeMode;
use sqlx::SqlitePool;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_CONFIGURED_WIRE_BYTES: usize = DEFAULT_MAX_WIRE_BYTES;
pub const MAX_CONFIGURED_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_CONFIGURED_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_HANDLER_TIMEOUT_MS: u64 = 300_000;
pub const MAX_INGRESS_READ_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_MAX_IN_FLIGHT_CONNECTIONS: usize = 64;
pub const MAX_CONFIGURED_IN_FLIGHT_CONNECTIONS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRuntimeConfig {
    pub bind_addr: String,
    pub db_url: String,
    pub receiver_audience: String,
    pub runtime_mode: RuntimeMode,
    pub verifier_key_path: Option<PathBuf>,
    pub verifier_key_id: Option<String>,
    pub ledger_path: Option<PathBuf>,
    pub trust_registry_path: Option<PathBuf>,
    pub max_wire_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_output_bytes: usize,
    pub handler_timeout: Duration,
    pub ingress_read_timeout: Duration,
    pub max_in_flight_connections: usize,
    pub allowed_evidence_adapters: Vec<String>,
    pub fixture_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigError {
    MissingProductionField(&'static str),
    PrototypeReceiverAudienceInProduction,
    InvalidNumber { field: &'static str, value: String },
    PayloadExceedsWireBudget,
    LedgerPathDoesNotMatchDbUrl,
    InvalidRuntimeMode(String),
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProductionField(field) => {
                write!(formatter, "production_verified requires explicit {field}")
            }
            Self::PrototypeReceiverAudienceInProduction => write!(
                formatter,
                "production_verified must not use fixture receiver audience {DEFAULT_RECEIVER_AUDIENCE}"
            ),
            Self::InvalidNumber { field, value } => {
                write!(formatter, "{field} must be a positive bounded integer, got {value:?}")
            }
            Self::PayloadExceedsWireBudget => {
                write!(formatter, "SECS_MAX_PAYLOAD_BYTES must not exceed SECS_MAX_WIRE_BYTES")
            }
            Self::LedgerPathDoesNotMatchDbUrl => write!(
                formatter,
                "SECS_LEDGER_PATH must match the SQLite path named by SECS_DB_URL"
            ),
            Self::InvalidRuntimeMode(value) => write!(formatter, "unsupported runtime mode {value:?}"),
        }
    }
}

impl std::error::Error for RuntimeConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Ready,
    NotReady,
    FixtureOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayReadiness {
    pub config_loaded: ReadinessStatus,
    pub ledger_ready: ReadinessStatus,
    pub trust_registry_ready: ReadinessStatus,
}

impl GatewayReadiness {
    pub fn is_ready_for_local_smoke(&self) -> bool {
        self.config_loaded == ReadinessStatus::Ready
            && self.ledger_ready == ReadinessStatus::Ready
            && matches!(
                self.trust_registry_ready,
                ReadinessStatus::Ready | ReadinessStatus::FixtureOnly
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupReadinessError {
    TrustRegistryNotReady { path: PathBuf, reason: String },
}

impl fmt::Display for StartupReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustRegistryNotReady { path, reason } => {
                write!(
                    formatter,
                    "production trust registry {:?} is not ready: {reason}",
                    path
                )
            }
        }
    }
}

impl std::error::Error for StartupReadinessError {}

impl GatewayRuntimeConfig {
    pub fn from_env() -> Result<Self, RuntimeConfigError> {
        let runtime_mode = match std::env::var("SECS_RUNTIME_MODE")
            .or_else(|_| std::env::var("SECZ_RUNTIME_MODE"))
        {
            Ok(value) => {
                RuntimeMode::parse(&value).ok_or(RuntimeConfigError::InvalidRuntimeMode(value))?
            }
            Err(_) => RuntimeMode::ProductionVerified,
        };

        let bind_addr = std::env::var("SECS_BIND_ADDR").ok();
        let db_url = std::env::var("SECS_DB_URL").ok();
        let receiver_audience = std::env::var("SECS_RECEIVER_AUDIENCE").ok();
        let verifier_key_path = std::env::var_os("SECS_VERIFIER_KEY_PATH").map(PathBuf::from);
        let verifier_key_id = std::env::var("SECS_VERIFIER_KEY_ID").ok();
        let trust_registry_path = std::env::var_os("SECS_TRUST_REGISTRY_PATH").map(PathBuf::from);
        let ledger_path = std::env::var_os("SECS_LEDGER_PATH").map(PathBuf::from);
        let max_wire_bytes = parse_usize_env(
            "SECS_MAX_WIRE_BYTES",
            DEFAULT_MAX_WIRE_BYTES,
            MAX_CONFIGURED_WIRE_BYTES,
        )?;
        let max_payload_bytes = parse_usize_env(
            "SECS_MAX_PAYLOAD_BYTES",
            1024 * 1024,
            MAX_CONFIGURED_PAYLOAD_BYTES,
        )?;
        let max_output_bytes = parse_usize_env(
            "SECS_MAX_OUTPUT_BYTES",
            1024 * 1024,
            MAX_CONFIGURED_OUTPUT_BYTES,
        )?;
        let handler_timeout = Duration::from_millis(parse_u64_env(
            "SECS_HANDLER_TIMEOUT_MS",
            ExecutionLimits::default().handler_timeout.as_millis() as u64,
            MAX_HANDLER_TIMEOUT_MS,
        )?);
        let ingress_read_timeout = Duration::from_millis(parse_u64_env(
            "SECS_INGRESS_READ_TIMEOUT_MS",
            DEFAULT_INGRESS_READ_TIMEOUT.as_millis() as u64,
            MAX_INGRESS_READ_TIMEOUT_MS,
        )?);
        let max_in_flight_connections = parse_usize_env(
            "SECS_MAX_IN_FLIGHT_CONNECTIONS",
            DEFAULT_MAX_IN_FLIGHT_CONNECTIONS,
            MAX_CONFIGURED_IN_FLIGHT_CONNECTIONS,
        )?;
        let allowed_evidence_adapters = parse_adapter_list(
            std::env::var("SECS_ALLOWED_EVIDENCE_ADAPTERS")
                .unwrap_or_else(|_| "local_static".to_string()),
        );

        match runtime_mode {
            RuntimeMode::ProductionVerified => {
                require_env_present("SECS_MAX_WIRE_BYTES")?;
                require_env_present("SECS_MAX_PAYLOAD_BYTES")?;
                require_env_present("SECS_MAX_OUTPUT_BYTES")?;
                require_env_present("SECS_HANDLER_TIMEOUT_MS")?;
                require_env_present("SECS_INGRESS_READ_TIMEOUT_MS")?;
                require_env_present("SECS_MAX_IN_FLIGHT_CONNECTIONS")?;
                Self::production(
                    required_env_string(bind_addr, "SECS_BIND_ADDR")?,
                    required_env_string(db_url, "SECS_DB_URL")?,
                    receiver_audience,
                    verifier_key_path,
                    verifier_key_id,
                    Some(required_env_path(ledger_path, "SECS_LEDGER_PATH")?),
                    trust_registry_path,
                    max_wire_bytes,
                    max_payload_bytes,
                    max_output_bytes,
                    handler_timeout,
                    ingress_read_timeout,
                    max_in_flight_connections,
                    allowed_evidence_adapters,
                )
            }
            RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel => Ok(Self {
                bind_addr: bind_addr.unwrap_or_else(|| "0.0.0.0:9001".to_string()),
                db_url: db_url.unwrap_or_else(|| "sqlite:node_telemetry.db?mode=rwc".to_string()),
                receiver_audience: receiver_audience
                    .unwrap_or_else(|| DEFAULT_RECEIVER_AUDIENCE.to_string()),
                runtime_mode,
                verifier_key_path,
                verifier_key_id,
                ledger_path,
                trust_registry_path,
                max_wire_bytes,
                max_payload_bytes,
                max_output_bytes,
                handler_timeout,
                ingress_read_timeout,
                max_in_flight_connections,
                allowed_evidence_adapters,
                fixture_only: true,
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn production_for_tests(
        bind_addr: &str,
        db_url: &str,
        receiver_audience: &str,
        verifier_key_path: &str,
        verifier_key_id: Option<&str>,
        trust_registry_path: &str,
        allowed_evidence_adapters: &str,
    ) -> Result<Self, RuntimeConfigError> {
        Self::production(
            bind_addr.to_string(),
            db_url.to_string(),
            Some(receiver_audience.to_string()),
            Some(PathBuf::from(verifier_key_path)),
            verifier_key_id.map(str::to_string),
            sqlite_path_from_db_url(db_url),
            Some(PathBuf::from(trust_registry_path)),
            DEFAULT_MAX_WIRE_BYTES,
            1024 * 1024,
            1024 * 1024,
            Duration::from_secs(30),
            DEFAULT_INGRESS_READ_TIMEOUT,
            DEFAULT_MAX_IN_FLIGHT_CONNECTIONS,
            parse_adapter_list(allowed_evidence_adapters.to_string()),
        )
    }

    pub fn local_fixture() -> Self {
        Self {
            bind_addr: "127.0.0.1:9001".to_string(),
            db_url: "sqlite::memory:".to_string(),
            receiver_audience: DEFAULT_RECEIVER_AUDIENCE.to_string(),
            runtime_mode: RuntimeMode::LocalDevPlaintext,
            verifier_key_path: None,
            verifier_key_id: None,
            ledger_path: None,
            trust_registry_path: None,
            max_wire_bytes: DEFAULT_MAX_WIRE_BYTES,
            max_payload_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            handler_timeout: Duration::from_secs(30),
            ingress_read_timeout: DEFAULT_INGRESS_READ_TIMEOUT,
            max_in_flight_connections: DEFAULT_MAX_IN_FLIGHT_CONNECTIONS,
            allowed_evidence_adapters: vec!["local_static".to_string()],
            fixture_only: true,
        }
    }

    pub fn execution_limits(&self) -> ExecutionLimits {
        ExecutionLimits {
            max_payload_bytes: self.max_payload_bytes,
            max_output_bytes: self.max_output_bytes,
            handler_timeout: self.handler_timeout,
        }
    }

    pub async fn readiness(&self, pool: &SqlitePool) -> Result<GatewayReadiness, sqlx::Error> {
        let ledger_ready = if sqlite_table_exists(pool, "events").await?
            && sqlite_table_exists(pool, "receipts").await?
        {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        };
        let trust_registry_ready = match self.runtime_mode {
            RuntimeMode::ProductionVerified => {
                if validate_trust_registry_file(self.trust_registry_path.as_deref()).is_ok() {
                    ReadinessStatus::Ready
                } else {
                    ReadinessStatus::NotReady
                }
            }
            RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel => {
                ReadinessStatus::FixtureOnly
            }
        };

        Ok(GatewayReadiness {
            config_loaded: ReadinessStatus::Ready,
            ledger_ready,
            trust_registry_ready,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn production(
        bind_addr: String,
        db_url: String,
        receiver_audience: Option<String>,
        verifier_key_path: Option<PathBuf>,
        verifier_key_id: Option<String>,
        ledger_path: Option<PathBuf>,
        trust_registry_path: Option<PathBuf>,
        max_wire_bytes: usize,
        max_payload_bytes: usize,
        max_output_bytes: usize,
        handler_timeout: Duration,
        ingress_read_timeout: Duration,
        max_in_flight_connections: usize,
        allowed_evidence_adapters: Vec<String>,
    ) -> Result<Self, RuntimeConfigError> {
        let receiver_audience = receiver_audience
            .filter(|value| !value.trim().is_empty())
            .ok_or(RuntimeConfigError::MissingProductionField(
                "SECS_RECEIVER_AUDIENCE",
            ))?;
        if receiver_audience == DEFAULT_RECEIVER_AUDIENCE {
            return Err(RuntimeConfigError::PrototypeReceiverAudienceInProduction);
        }
        let verifier_key_path = verifier_key_path
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(RuntimeConfigError::MissingProductionField(
                "SECS_VERIFIER_KEY_PATH",
            ))?;
        let ledger_path = ledger_path
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(RuntimeConfigError::MissingProductionField(
                "SECS_LEDGER_PATH",
            ))?;
        if sqlite_path_from_db_url(&db_url).as_deref() != Some(ledger_path.as_path()) {
            return Err(RuntimeConfigError::LedgerPathDoesNotMatchDbUrl);
        }
        let trust_registry_path = trust_registry_path
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(RuntimeConfigError::MissingProductionField(
                "SECS_TRUST_REGISTRY_PATH",
            ))?;
        validate_limits(max_wire_bytes, max_payload_bytes)?;
        Ok(Self {
            bind_addr,
            db_url,
            receiver_audience,
            runtime_mode: RuntimeMode::ProductionVerified,
            verifier_key_path: Some(verifier_key_path),
            verifier_key_id,
            ledger_path: Some(ledger_path),
            trust_registry_path: Some(trust_registry_path),
            max_wire_bytes,
            max_payload_bytes,
            max_output_bytes,
            handler_timeout,
            ingress_read_timeout,
            max_in_flight_connections,
            allowed_evidence_adapters,
            fixture_only: false,
        })
    }
}

pub fn validate_production_startup_readiness(
    config: &GatewayRuntimeConfig,
) -> Result<(), StartupReadinessError> {
    if config.runtime_mode != RuntimeMode::ProductionVerified {
        return Ok(());
    }
    validate_trust_registry_file(config.trust_registry_path.as_deref()).map_err(|reason| {
        StartupReadinessError::TrustRegistryNotReady {
            path: config.trust_registry_path.clone().unwrap_or_default(),
            reason,
        }
    })
}

async fn sqlite_table_exists(pool: &SqlitePool, table_name: &str) -> Result<bool, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table_name)
            .fetch_one(pool)
            .await?;
    Ok(count.0 > 0)
}

fn validate_trust_registry_file(path: Option<&Path>) -> Result<(), String> {
    let path = path.ok_or_else(|| "missing path".to_string())?;
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("path is not a regular file".to_string());
    }
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn parse_usize_env(
    field: &'static str,
    default: usize,
    max: usize,
) -> Result<usize, RuntimeConfigError> {
    match std::env::var(field) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|parsed| *parsed > 0 && *parsed <= max)
            .ok_or(RuntimeConfigError::InvalidNumber { field, value }),
        Err(_) => Ok(default),
    }
}

fn parse_u64_env(field: &'static str, default: u64, max: u64) -> Result<u64, RuntimeConfigError> {
    match std::env::var(field) {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|parsed| *parsed > 0 && *parsed <= max)
            .ok_or(RuntimeConfigError::InvalidNumber { field, value }),
        Err(_) => Ok(default),
    }
}

fn required_env_string(
    value: Option<String>,
    field: &'static str,
) -> Result<String, RuntimeConfigError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or(RuntimeConfigError::MissingProductionField(field))
}

fn require_env_present(field: &'static str) -> Result<(), RuntimeConfigError> {
    match std::env::var(field) {
        Ok(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(RuntimeConfigError::MissingProductionField(field)),
    }
}

fn required_env_path(
    value: Option<PathBuf>,
    field: &'static str,
) -> Result<PathBuf, RuntimeConfigError> {
    value
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(RuntimeConfigError::MissingProductionField(field))
}

fn validate_limits(
    max_wire_bytes: usize,
    max_payload_bytes: usize,
) -> Result<(), RuntimeConfigError> {
    if max_payload_bytes > max_wire_bytes {
        return Err(RuntimeConfigError::PayloadExceedsWireBudget);
    }
    Ok(())
}

fn sqlite_path_from_db_url(db_url: &str) -> Option<PathBuf> {
    let without_scheme = db_url
        .strip_prefix("sqlite://")
        .or_else(|| db_url.strip_prefix("sqlite:"))?;
    if without_scheme == ":memory:" {
        return None;
    }
    let path = without_scheme
        .split_once('?')
        .map_or(without_scheme, |(path, _)| path);
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn parse_adapter_list(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}
