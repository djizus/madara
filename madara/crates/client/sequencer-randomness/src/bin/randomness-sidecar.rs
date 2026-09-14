#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mc_sequencer_randomness::service::run().await
}
