use server::config::GatewayRuntimeConfig;
use server::ingress::run_gateway_with_config;

#[tokio::main]
async fn main() {
    let config = GatewayRuntimeConfig::from_env()
        .unwrap_or_else(|error| panic!("secS gateway: invalid runtime config - {error}"));
    run_gateway_with_config(config, "secS prototype gateway").await;
}
