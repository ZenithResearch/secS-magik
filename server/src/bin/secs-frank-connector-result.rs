//! Fixed connector-journal result attester. No provider, shell or raw signer.
use server::{FrankConnectorResultAuthority, FrankResultMode};
use std::{
    io::{Read, Write},
    path::Path,
};

async fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 6 || args[2] != "--config" || args[4] != "--config-sha256" {
        return Err(());
    }
    let mode = match args[1].to_str() {
        Some("attest") => FrankResultMode::Attest,
        Some("resume") => FrankResultMode::Resume,
        Some("renew") => FrankResultMode::Renew,
        _ => return Err(()),
    };
    let h = args[5].to_str().ok_or(())?;
    if h.len() != 64
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    let mut pin = [0u8; 32];
    for (i, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|_| ())?;
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(16_385)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() > 16_384 {
        return Err(());
    }
    let authority =
        FrankConnectorResultAuthority::open_pinned_owner_configuration(Path::new(&args[3]), pin)
            .await
            .map_err(|_| ())?;
    let output = authority.execute(mode, &input).await.map_err(|_| ())?;
    std::io::stdout().write_all(&output).map_err(|_| ())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if run().await.is_err() {
        eprintln!("{{\"error\":\"native_connector_result_authority_rejected\"}}");
        std::process::exit(2);
    }
}
