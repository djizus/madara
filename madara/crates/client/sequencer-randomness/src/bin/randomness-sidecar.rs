#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()?).init();
    mc_sequencer_randomness::service::run().await
}
