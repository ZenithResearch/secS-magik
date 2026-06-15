//! `secs-permctl` — operator CLI for authoring and inspecting receiver-local
//! permission policies (M13.4a). Thin clap wrapper over `server::permctl`.
//!
//! Receiver-local policy only — no Dregg authority, deployment proof, or public
//! auditability claims.

use clap::{Parser, Subcommand};
use server::permctl;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "secs-permctl",
    about = "Author and inspect receiver-local secS permission policies"
)]
struct Cli {
    /// Path to the JSON permission policy file.
    #[arg(long, global = true, default_value = "secs-permissions.json")]
    policy: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the records in the policy file.
    List,
    /// Add a permission record and save.
    Grant(GrantArgs),
    /// Revoke matching records (by caller/opcode/operation/resource) and save.
    Revoke(MatchArgs),
    /// Evaluate a request against the policy. Prints ALLOW or DENY:<reason>.
    Evaluate(EvaluateArgs),
}

#[derive(clap::Args)]
struct GrantArgs {
    #[arg(long)]
    caller: String,
    /// Opcode, e.g. 0x50 or 80.
    #[arg(long, value_parser = parse_opcode)]
    opcode: u8,
    #[arg(long)]
    operation: String,
    #[arg(long)]
    resource: String,
    /// Treat the resource as a prefix scope rather than an exact match.
    #[arg(long)]
    prefix: bool,
    /// Make this a deny record (deny wins over allow).
    #[arg(long)]
    deny: bool,
    #[arg(long, default_value_t = 0)]
    not_before: u64,
    #[arg(long, default_value_t = u64::MAX)]
    not_after: u64,
}

#[derive(clap::Args)]
struct MatchArgs {
    #[arg(long)]
    caller: String,
    #[arg(long, value_parser = parse_opcode)]
    opcode: u8,
    #[arg(long)]
    operation: String,
    /// The resource value (exact value or prefix string) to match.
    #[arg(long)]
    resource: String,
}

#[derive(clap::Args)]
struct EvaluateArgs {
    #[arg(long)]
    caller: String,
    #[arg(long, value_parser = parse_opcode)]
    opcode: u8,
    #[arg(long)]
    operation: String,
    #[arg(long)]
    resource: String,
    /// Evaluation time (unix seconds). Defaults to now.
    #[arg(long)]
    now: Option<u64>,
}

fn parse_opcode(value: &str) -> Result<u8, String> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16)
    } else {
        value.parse::<u8>()
    };
    parsed.map_err(|_| format!("invalid opcode `{value}` (use 0x50 or 80)"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let records = match permctl::load_records(&cli.policy) {
        Ok(records) => records,
        Err(err) => {
            eprintln!("secs-permctl: {}", err.message());
            return ExitCode::FAILURE;
        }
    };

    match cli.command {
        Command::List => {
            let lines = permctl::list_lines(&records);
            if lines.is_empty() {
                println!("(no permission records)");
            } else {
                for line in lines {
                    println!("{line}");
                }
            }
            ExitCode::SUCCESS
        }
        Command::Grant(args) => {
            let record = permctl::build_record(
                args.caller,
                args.opcode,
                args.operation,
                args.resource,
                args.prefix,
                args.deny,
                args.not_before,
                args.not_after,
            );
            let updated = permctl::grant(records, record);
            match permctl::save_records(&cli.policy, &updated) {
                Ok(()) => {
                    println!("granted; {} record(s) total", updated.len());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("secs-permctl: {}", err.message());
                    ExitCode::FAILURE
                }
            }
        }
        Command::Revoke(args) => {
            let (updated, revoked) = permctl::revoke(
                records,
                &args.caller,
                args.opcode,
                &args.operation,
                &args.resource,
            );
            if revoked == 0 {
                println!("no matching active records to revoke");
                return ExitCode::SUCCESS;
            }
            match permctl::save_records(&cli.policy, &updated) {
                Ok(()) => {
                    println!("revoked {revoked} record(s)");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("secs-permctl: {}", err.message());
                    ExitCode::FAILURE
                }
            }
        }
        Command::Evaluate(args) => {
            let now = args.now.unwrap_or_else(unix_now);
            match permctl::evaluate(
                records,
                &args.caller,
                args.opcode,
                &args.operation,
                &args.resource,
                now,
            ) {
                Ok(()) => {
                    println!("ALLOW");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
                    println!("DENY:{}", reason.code());
                    ExitCode::FAILURE
                }
            }
        }
    }
}
