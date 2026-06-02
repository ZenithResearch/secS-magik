use server::ingress::run_prototype_gateway;

#[tokio::main]
async fn main() {
    run_prototype_gateway(
        "0.0.0.0:9001",
        "sqlite:node_telemetry.db?mode=rwc",
        "secS prototype gateway",
    )
    .await;
}
