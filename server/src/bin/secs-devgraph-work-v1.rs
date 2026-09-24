use clap::Parser;
use server::devgraph_work_cli::{run, WorkCli};
#[tokio::main]
async fn main() {
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "admin") {
        let args = std::iter::once(std::ffi::OsString::from("secs-devgraph-work-v1 admin"))
            .chain(std::env::args_os().skip(2));
        let result = match server::devgraph_work_admin::AdminCli::try_parse_from(args) {
            Ok(cli) => server::devgraph_work_admin::run(cli).await,
            Err(error) if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp) => {
                print!("{error}");
                return;
            }
            Err(_) => Err("invalid_arguments"),
        };
        match result {
            Ok(value) => println!("{value}"),
            Err(reason) => {
                eprintln!("{{\"error\":\"{reason}\"}}");
                std::process::exit(2);
            }
        }
        return;
    }
    let cli = match WorkCli::try_parse() {
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
