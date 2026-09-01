use clap::Parser;
use server::devgraph_issue_create_wallet_cli::{run, DevgraphIssueCreateWalletCli};

#[tokio::main]
async fn main() {
    let cli = match DevgraphIssueCreateWalletCli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return;
        }
        Err(_) => {
            eprintln!("{{\"error\":\"invalid_arguments\",\"ok\":false}}");
            std::process::exit(2);
        }
    };
    match run(cli).await {
        Ok(summary) => println!("{}", summary.canonical_json()),
        Err(error) => {
            eprintln!("{}", error.canonical_json());
            std::process::exit(1);
        }
    }
}
