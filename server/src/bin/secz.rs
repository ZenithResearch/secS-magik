use server::ingress::run_prototype_gateway;

#[tokio::main]
async fn main() {
    run_prototype_gateway(
        "127.0.0.1:9001",
        "sqlite:node_telemetry.db?mode=rwc",
        "secZ compatibility gateway",
    )
    .await;
}
