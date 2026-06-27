use server::ingress::run_prototype_gateway;
use server::public_audit_cli::verify_public_audit_bundle_file;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("audit") {
        std::process::exit(run_audit_command(&args[2..]));
    }

    run_prototype_gateway(
        "127.0.0.1:9001",
        "sqlite:node_telemetry.db?mode=rwc",
        "secZ compatibility gateway",
    )
    .await;
}

fn run_audit_command(args: &[String]) -> i32 {
    match args {
        [command, bundle_path] if command == "verify" => {
            match verify_public_audit_bundle_file(bundle_path) {
                Ok(report) => {
                    println!("{}", report.render_summary());
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    2
                }
            }
        }
        _ => {
            eprintln!("usage: secz audit verify <bundle.json>");
            64
        }
    }
}
