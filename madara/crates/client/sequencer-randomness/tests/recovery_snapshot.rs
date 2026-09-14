use mc_sequencer_randomness::journal::{ChainProgress, Journal};
use serde::Deserialize;
use starknet_types_core::felt::Felt;

#[derive(Deserialize)]
struct Snapshot {
    order: u64,
    binding: Felt,
    state: Felt,
    result: Felt,
}

#[tokio::test]
#[ignore = "requires a fenced local survivor and captured chain progress; reads the survivor without promotion"]
async fn survivor_prefix_matches_chain_before_promotion() {
    let connection = std::env::var("RANDOMNESS_SURVIVOR").unwrap();
    let epoch = std::env::var("RANDOMNESS_RECOVERY_EPOCH").unwrap().parse().unwrap();
    let path = std::env::var("RANDOMNESS_CHAIN_PROGRESS").unwrap();
    let captured: Vec<Snapshot> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let chain: Vec<_> = captured
        .into_iter()
        .map(|row| ChainProgress { order: row.order, binding: row.binding, state: row.state, result: row.result })
        .collect();
    // Both handles deliberately read the one survivor. This proves prefix integrity, not two-copy durability.
    let mut journal = Journal::connect(&connection, &connection, epoch).await.unwrap();
    let records = journal.recover(&chain).await.unwrap();
    assert!(records.len() >= chain.len(), "chain extends beyond the surviving journal");
    assert!(!records.is_empty(), "the survivor must retain exercised actions");
    for (record, progress) in records.iter().zip(chain) {
        assert_eq!(record.envelope.binding().unwrap(), progress.binding);
        assert_eq!(record.result, Some(progress.result));
        assert_eq!(record.following_state, Some(progress.state));
    }
}
