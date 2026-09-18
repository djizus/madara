use std::collections::BTreeSet;

use crate::versions::user::v0_10_0::StarknetWsRpcApiV0_10_0Server;
use crate::versions::user::v0_10_2::StarknetWsRpcApiV0_10_2Server;
use crate::{rpc_api_user, test_utils::rpc_test_setup};

const LEGACY_WS_METHODS: &[&str] = &[
    "starknet_V0_8_1_subscribeNewHeads",
    "starknet_V0_8_1_subscribeEvents",
    "starknet_V0_8_1_subscribeTransactionStatus",
    "starknet_V0_8_1_subscribePendingTransactions",
    "starknet_V0_8_1_unsubscribe",
    "starknet_V0_9_0_subscribeNewHeads",
    "starknet_V0_9_0_subscribeEvents",
    "starknet_V0_9_0_subscribeTransactionStatus",
    "starknet_V0_9_0_subscribeNewTransactions",
    "starknet_V0_9_0_subscribeNewTransactionReceipts",
    "starknet_V0_9_0_subscribePendingTransactions",
    "starknet_V0_9_0_unsubscribe",
];

fn ws_method_names<Context>(module: jsonrpsee::RpcModule<Context>) -> BTreeSet<String> {
    module.method_names().map(str::to_owned).collect()
}

#[test]
fn merged_rpc_does_not_expose_legacy_ws_methods() {
    let (_, starknet) = rpc_test_setup();
    let methods = ws_method_names(rpc_api_user(&starknet).expect("Building user RPC module"));

    for method in LEGACY_WS_METHODS {
        assert!(!methods.contains(*method));
    }
}

#[tokio::test]
async fn legacy_ws_methods_return_method_not_found() {
    let (_, starknet) = rpc_test_setup();
    let module = rpc_api_user(&starknet).expect("Building user RPC module");

    for method in LEGACY_WS_METHODS {
        let request = format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":1}}"#);
        let (response, _) = module.raw_json_request(&request, 1).await.expect("Legacy WS method request");
        let response: serde_json::Value = serde_json::from_str(&response).expect("Parsing JSON-RPC response");

        assert_eq!(response["error"]["code"], -32601, "{method} should return method not found");
    }
}

#[test]
fn v0_10_0_ws_surface_uses_new_transaction_methods() {
    let (_, starknet) = rpc_test_setup();
    let methods = ws_method_names(StarknetWsRpcApiV0_10_0Server::into_rpc(starknet));

    assert!(methods.contains("starknet_V0_10_0_subscribeNewHeads"));
    assert!(methods.contains("starknet_V0_10_0_subscribeEvents"));
    assert!(methods.contains("starknet_V0_10_0_subscribeTransactionStatus"));
    assert!(methods.contains("starknet_V0_10_0_subscribeNewTransactions"));
    assert!(methods.contains("starknet_V0_10_0_subscribeNewTransactionReceipts"));
    assert!(methods.contains("starknet_V0_10_0_unsubscribe"));
    assert!(!methods.contains("starknet_V0_10_0_subscribePendingTransactions"));
}

#[test]
fn v0_10_2_ws_surface_matches_new_transaction_spec_methods() {
    let (_, starknet) = rpc_test_setup();
    let methods = ws_method_names(StarknetWsRpcApiV0_10_2Server::into_rpc(starknet));

    assert!(methods.contains("starknet_V0_10_2_subscribeNewHeads"));
    assert!(methods.contains("starknet_V0_10_2_subscribeEvents"));
    assert!(methods.contains("starknet_V0_10_2_subscribeTransactionStatus"));
    assert!(methods.contains("starknet_V0_10_2_subscribeNewTransactions"));
    assert!(methods.contains("starknet_V0_10_2_subscribeNewTransactionReceipts"));
    assert!(methods.contains("starknet_V0_10_2_unsubscribe"));
    assert!(!methods.contains("starknet_V0_10_2_subscribePendingTransactions"));
}

use crate::{test_utils::TestTxStatusWatcher, Starknet};
use mp_block::{header::PreconfirmedHeader, FullBlockWithoutCommitments};
use mp_convert::Felt;
use serde_json::Value;
use std::time::Duration;

const TX_HASH: Felt = Felt::from_hex_unchecked("0x3ccaabf599097d1965e1ef8317b830e76eb681016722c9364ed6e59f3252908");

fn add_block_at_with_hash(
    backend: &std::sync::Arc<mc_db::MadaraBackend>,
    n: u64,
) -> (Felt, mp_rpc::v0_10_2::BlockHeader) {
    let block_hash = backend
        .write_access()
        .add_full_block_with_classes(
            &FullBlockWithoutCommitments {
                header: PreconfirmedHeader { block_number: n, ..Default::default() },
                state_diff: mp_state_update::StateDiff::default(),
                transactions: vec![],
                events: vec![],
            },
            &[],
            false,
        )
        .expect("Storing block")
        .block_hash;

    let header = backend
        .block_view_on_confirmed(n)
        .expect("Retrieving block view")
        .get_block_info()
        .expect("Retrieving block info")
        .to_rpc_v0_10();

    (block_hash, header)
}

fn add_block_at(backend: &std::sync::Arc<mc_db::MadaraBackend>, n: u64) -> mp_rpc::v0_10_2::BlockHeader {
    add_block_at_with_hash(backend, n).1
}

async fn wait_for_active_subscriptions(starknet: &Starknet, expected: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if starknet.active_ws_subscription_count() == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Timed out waiting for websocket subscription cleanup");
}

#[rstest::rstest]
#[case("subscribeNewHeads")]
#[case("subscribeEvents")]
#[case("subscribeNewTransactions")]
#[case("subscribeNewTransactionReceipts")]
#[case("subscribeTransactionStatus")]
#[tokio::test]
async fn unsubscribe_closes_without_error_notification(
    #[case] method: &str,
    #[values("V0_10_0", "V0_10_2")] version: &str,
) {
    let (backend, mut starknet) = rpc_test_setup();
    add_block_at(&backend, 0);
    starknet.set_tx_status_watcher(Some(TestTxStatusWatcher::new()));
    let module = match version {
        "V0_10_0" => StarknetWsRpcApiV0_10_0Server::into_rpc(starknet.clone()),
        _ => StarknetWsRpcApiV0_10_2Server::into_rpc(starknet.clone()),
    };
    let params = if method == "subscribeTransactionStatus" {
        serde_json::json!({ "transaction_hash": TX_HASH })
    } else {
        serde_json::json!({})
    };
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": format!("starknet_{version}_{method}"), "params": params,
    });
    let (response, mut frames) = module.raw_json_request(&request.to_string(), 16).await.unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    let id = response["result"].as_u64().expect("Subscription id");
    wait_for_active_subscriptions(&starknet, 1).await;

    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 2,
        "method": format!("starknet_{version}_unsubscribe"), "params": [id.to_string()],
    });
    let (response, _) = module.raw_json_request(&request.to_string(), 16).await.unwrap();
    assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["result"], true);
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(frame) = frames.recv().await {
            let frame: Value = serde_json::from_str(&frame).expect("Valid subscription JSON");
            assert!(frame["params"].get("error").is_none(), "{frame}");
        }
    })
    .await
    .expect("Unsubscribe must close the stream");
    wait_for_active_subscriptions(&starknet, 0).await;
}

#[tokio::test]
async fn subscription_failure_emits_valid_json() {
    let (_backend, starknet) = rpc_test_setup();
    // An accepted subscription without a status watcher fails on the server.
    let module = StarknetWsRpcApiV0_10_2Server::into_rpc(starknet);
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "starknet_V0_10_2_subscribeTransactionStatus",
        "params": { "transaction_hash": TX_HASH },
    });
    let (_, mut frames) = module.raw_json_request(&request.to_string(), 16).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), frames.recv()).await.unwrap().unwrap();
    let frame: Value = serde_json::from_str(&frame).expect("Valid error notification JSON");
    assert_eq!(frame["params"]["error"], "Internal error");
}
