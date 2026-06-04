pub mod config;
pub mod evidence;
pub mod gateway;
pub mod identity;
pub mod ingress;
pub mod ledger;
pub mod manifest;
pub mod ontology;
pub mod payload;
pub mod receipt;
pub mod runtime_mode;
pub mod schema;
pub mod session;
pub mod verifier;

use crate::session::SessionStore;
use async_trait::async_trait;
use libsec_core::ZenithPacket;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

#[async_trait]
pub trait PayloadRouter: Send + Sync {
    async fn route(&self, store: &SessionStore, opcode: u8, payload: Vec<u8>);
}

async fn handle_client(
    store: Arc<SessionStore>,
    router: Arc<dyn PayloadRouter>,
    mut socket: TcpStream,
) {
    let mut buf = [0; 1024];
    loop {
        let n = socket
            .read(&mut buf)
            .await
            .expect("failed to read data from socket");
        if n == 0 {
            return;
        }
        if n > 0 {
            match bincode::deserialize::<ZenithPacket>(&buf[..n]) {
                Ok(packet) => {
                    println!("Packet Received: Opcode {}", packet.opcode);
                    if !packet.proof.is_empty() {
                        println!("Validating Proof...");
                    }
                    router
                        .route(&store, packet.opcode, packet.encrypted_payload)
                        .await;
                }
                Err(e) => eprintln!("Failed to deserialize packet: {}", e),
            }
        }
    }
}

pub async fn run_node(addr: &str, store: Arc<SessionStore>, router: Arc<dyn PayloadRouter>) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    println!("Node listening on {}", addr);
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let store_clone = store.clone();
                let router_clone = router.clone();
                tokio::spawn(async move {
                    handle_client(store_clone, router_clone, socket).await;
                });
            }
            Err(e) => eprintln!("Failed to accept connection: {}", e),
        }
    }
}
