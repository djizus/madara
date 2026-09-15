#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 2 && arguments[0] == "--check-native-schema" {
        return mc_sequencer_randomness::service::validate_native_schema(std::path::Path::new(&arguments[1]));
    }
    if !arguments.is_empty() {
        anyhow::bail!("usage: randomness-sidecar [--check-native-schema PATH]");
    }
    tracing_subscriber::fmt().json().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()?).init();
    mc_sequencer_randomness::service::run().await
}
