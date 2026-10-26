use secs_local_admin_rpc_v1::*;
use std::path::PathBuf;
fn run() -> Result<serde_json::Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--instance-id" {
        return Err("invalid_arguments");
    }
    // HOME is not a caller-supplied authority/configuration selector.
    let home = unsafe {
        let entry = libc::getpwuid(libc::geteuid());
        if entry.is_null() {
            return Err("setup_required");
        };
        PathBuf::from(
            std::ffi::CStr::from_ptr((*entry).pw_dir)
                .to_str()
                .map_err(|_| "setup_required")?,
        )
    };
    let c = load(&home, &args[2])?;
    let raw = read_request(
        0,
        deadline.saturating_duration_since(std::time::Instant::now()),
    )?;
    let request: Request = castalia_wallet_presentation::parse(&raw, REQUEST_MAX)?;
    let value = invoke_deadline(&c, &request, &home, deadline)?;
    Ok(value)
}
fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"schema":"secs.local-admin-error.v1","error":error})
            );
            std::process::exit(1)
        }
    }
}
