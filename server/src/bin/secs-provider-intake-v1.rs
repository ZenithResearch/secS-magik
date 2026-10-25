use clap::Parser;
use server::provider_intake_cli::{run, ProviderIntakeCli};
use std::io::{self, Write};

fn main() {
    let cli = match ProviderIntakeCli::try_parse() {
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
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    if let Err(error) = run(cli, &mut input, &mut output) {
        let _ = output.flush();
        eprintln!("{}", error.canonical_json());
        std::process::exit(1);
    }
}
