use clap::Parser;
use server::devgraph_issue_create_cli::{run, DevgraphIssueCreateCli};

#[tokio::main]
async fn main() {
    let cli = DevgraphIssueCreateCli::parse();
    match run(cli).await {
        Ok(summary) => {
            println!("{}", summary.canonical_json());
        }
        Err(error) => {
            eprintln!("{}", error.canonical_json());
            std::process::exit(1);
        }
    }
}
