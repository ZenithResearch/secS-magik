use clap::Parser;
use server::devgraph_work_v2_cli::{run, Cli};
#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp) => {
            print!("{error}");
            return;
        }
        Err(_) => {
            eprintln!("{{\"error\":\"invalid_arguments\"}}");
            std::process::exit(2);
        }
    };
    match run(cli).await {
        Ok(()) => println!("{{\"ok\":true,\"output_written\":true}}"),
        Err(reason) => {
            eprintln!("{{\"error\":\"{reason}\"}}");
            std::process::exit(2);
        }
    }
}
