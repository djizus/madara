use crate::protocol::Intent;
use anyhow::{bail, Context, Result};
use serde_json::Value;
use starknet_core::{
    types::{BlockId, BlockStatus, BlockTag, Felt, FunctionCall, MaybePreConfirmedBlockWithTxHashes, StarknetError},
    utils::get_selector_from_name,
};
use starknet_providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError};
use starknet_types_core::hash::{Poseidon, StarkHash};

/// The schema fixes the command layout; accepted arguments already persist in the journal.
pub(crate) struct SettlementChecks {
    tag: Felt,
    l2: Option<JsonRpcClient<HttpTransport>>,
}

impl SettlementChecks {
    pub(crate) fn load(schema: &str, l2: Option<&str>) -> Result<Self> {
        let schema: Value = serde_json::from_str(schema)?;
        let types = &schema["types"];
        let commands =
            types["world_native::commands::Command"]["variants"].as_array().context("missing native command schema")?;
        let tag = commands
            .iter()
            .position(|variant| variant["name"] == "SettleBlitz")
            .context("missing settlement command")?;
        require_members(
            types,
            commands[tag]["type"].as_str().context("missing settlement payload type")?,
            &[
                ("name", "core::felt252"),
                ("owner", "core::starknet::contract_address::ContractAddress"),
                ("cosmetics_block_hash", "core::felt252"),
                ("cosmetics_block_number", "core::integer::u64"),
                ("cosmetics", "core::array::Span::<world_native::settlement::AcceptedCosmetic>"),
                ("grant_starting_troops", "core::bool"),
            ],
        )?;
        require_members(
            types,
            "world_native::settlement::AcceptedCosmetic",
            &[
                ("token_id", "core::integer::u128"),
                ("owner", "core::starknet::contract_address::ContractAddress"),
                ("attributes", "core::integer::u128"),
            ],
        )?;
        let l2 = l2
            .map(|url| Ok::<_, anyhow::Error>(JsonRpcClient::new(HttpTransport::new(url.parse::<url::Url>()?))))
            .transpose()?;
        Ok(Self { tag: Felt::from(tag as u64), l2 })
    }

    pub(crate) fn is_settlement(&self, intent: &Intent) -> bool {
        intent.arguments.first() == Some(&self.tag)
    }

    /// Called only for a new proposal. Recovery reads the retained arguments without external calls.
    pub(crate) async fn verify(&self, intent: &Intent, policy: &[Felt]) -> Result<bool> {
        tokio::time::timeout(std::time::Duration::from_secs(10), self.verify_claims(intent, policy))
            .await
            .context("cosmetic admission timed out before acceptance")?
    }

    async fn verify_claims(&self, intent: &Intent, policy: &[Felt]) -> Result<bool> {
        let Some(claims) = Claims::decode(intent) else {
            return Ok(false);
        };
        let [owner, collection, timelock, limit, _game_end] = policy else {
            bail!("malformed settlement admission policy");
        };
        if claims.owner != *owner || *owner == Felt::ZERO {
            return Ok(false);
        }
        if *collection == Felt::ZERO || *timelock == Felt::ZERO {
            return Ok(true);
        }
        let limit = u8::try_from(*limit).context("invalid cosmetic limit")?;
        if claims.tokens.len() > usize::from(limit) {
            return Ok(false);
        }
        if claims.tokens.is_empty() {
            return Ok(true);
        }
        let l2 = self.l2.as_ref().context("cosmetic admission requires RANDOMNESS_L2_RPC_URL")?;
        let finalized = l2.get_block_with_tx_hashes(BlockId::Tag(BlockTag::L1Accepted)).await?;
        let MaybePreConfirmedBlockWithTxHashes::Block(finalized) = finalized else {
            bail!("L2 provider returned a pre-confirmed block for l1_accepted");
        };
        if finalized.status != BlockStatus::AcceptedOnL1 {
            bail!("L2 provider returned an unfinalized block for l1_accepted");
        }
        if claims.block_hash != finalized.block_hash || claims.block_number != finalized.block_number {
            return Ok(false);
        }
        let block = BlockId::Hash(finalized.block_hash);
        for token in claims.tokens {
            if token.owner != *owner || token.attributes == 0 {
                return Ok(false);
            }
            let actual_owner = read_token(l2, *collection, "owner_of", token.id, block).await?;
            if actual_owner.as_deref() != Some(&[*owner]) {
                return Ok(false);
            }
            let actual_attributes = read_token(l2, *collection, "get_metadata_raw", token.id, block).await?;
            if actual_attributes.as_deref() != Some(&[token.attributes.into()]) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn require_members(types: &Value, name: &str, expected: &[(&str, &str)]) -> Result<()> {
    let members = types[name]["members"].as_array().context("missing native settlement type")?;
    if members.len() != expected.len()
        || members
            .iter()
            .zip(expected)
            .any(|(member, (name, value_type))| member["name"] != *name || member["type"] != *value_type)
    {
        bail!("native settlement schema changed: {name}");
    }
    Ok(())
}

struct Token {
    id: u128,
    owner: Felt,
    attributes: u128,
}
struct Claims {
    owner: Felt,
    block_hash: Felt,
    block_number: u64,
    tokens: Vec<Token>,
}
impl Claims {
    fn decode(intent: &Intent) -> Option<Self> {
        const COMMAND_TAG: Felt = Felt::from_hex_unchecked("0x455445524e554d5f434f4d4d414e44");
        let mut commitment = vec![COMMAND_TAG, Felt::ONE];
        commitment.extend_from_slice(&intent.arguments);
        if Poseidon::hash_array(&commitment) != intent.command {
            return None;
        }
        let fields = &intent.arguments;
        let count = usize::try_from(u32::try_from(*fields.get(5)?).ok()?).ok()?;
        if fields.len() != 7usize.checked_add(count.checked_mul(3)?)? {
            return None;
        }
        if *fields.last()? != Felt::ZERO && *fields.last()? != Felt::ONE {
            return None;
        }
        let tokens = fields[6..fields.len() - 1]
            .chunks_exact(3)
            .map(|token| {
                Some(Token { id: token[0].try_into().ok()?, owner: token[1], attributes: token[2].try_into().ok()? })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { owner: fields[2], block_hash: fields[3], block_number: fields[4].try_into().ok()?, tokens })
    }
}

async fn read_token(
    l2: &JsonRpcClient<HttpTransport>,
    collection: Felt,
    method: &str,
    id: u128,
    block: BlockId,
) -> Result<Option<Vec<Felt>>> {
    match l2
        .call(
            FunctionCall {
                contract_address: collection,
                entry_point_selector: get_selector_from_name(method)?,
                calldata: vec![id.into(), Felt::ZERO],
            },
            block,
        )
        .await
    {
        Ok(values) => Ok(Some(values)),
        Err(ProviderError::StarknetError(StarknetError::ContractError(_))) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(arguments: Vec<Felt>) -> Intent {
        let mut fields = vec![Felt::from_hex_unchecked("0x455445524e554d5f434f4d4d414e44"), Felt::ONE];
        fields.extend_from_slice(&arguments);
        Intent {
            chain: Felt::ONE,
            deployment: Felt::ONE,
            game: Felt::ONE,
            actor: 456u64.into(),
            nonce: 0,
            command: Poseidon::hash_array(&fields),
            rules: Felt::ONE,
            valid_from: 1,
            valid_until: 2,
            last_order: 1,
            arguments,
        }
    }

    fn finalized_block() -> Value {
        serde_json::json!({
            "status": "ACCEPTED_ON_L1", "block_hash": "0xabc", "block_number": 2,
            "parent_hash": "0x0", "new_root": "0x0", "timestamp": 1,
            "sequencer_address": "0x1", "starknet_version": "0.14.0",
            "l1_gas_price": {"price_in_fri": "0x1", "price_in_wei": "0x1"},
            "l2_gas_price": {"price_in_fri": "0x1", "price_in_wei": "0x1"},
            "l1_data_gas_price": {"price_in_fri": "0x1", "price_in_wei": "0x1"},
            "l1_da_mode": "BLOB", "transactions": [],
            "event_commitment": "0x0", "transaction_commitment": "0x0",
            "receipt_commitment": "0x0", "state_diff_commitment": "0x0",
            "event_count": 0, "transaction_count": 0, "state_diff_length": 0
        })
    }

    #[test]
    fn signed_claims_reject_truncation_extra_fields_and_noncanonical_values() {
        let fields = vec![
            11u64.into(),
            99u64.into(),
            123u64.into(),
            Felt::from_hex_unchecked("0xabc"),
            Felt::TWO,
            Felt::ONE,
            19u64.into(),
            123u64.into(),
            321u64.into(),
            Felt::ZERO,
        ];
        let valid = action(fields.clone());
        let claims = Claims::decode(&valid).unwrap();
        assert_eq!(claims.tokens[0].id, 19);
        assert_eq!(claims.tokens[0].attributes, 321);
        let mut changed = valid.clone();
        changed.arguments[8] = 777u64.into();
        assert!(Claims::decode(&changed).is_none());
        for length in 0..fields.len() {
            assert!(Claims::decode(&action(fields[..length].to_vec())).is_none());
        }
        let mut extended = fields.clone();
        extended.push(Felt::ZERO);
        assert!(Claims::decode(&action(extended)).is_none());
        let mut invalid_bool = fields.clone();
        invalid_bool[9] = Felt::TWO;
        assert!(Claims::decode(&action(invalid_bool)).is_none());
        let mut too_wide = fields;
        too_wide[8] = Felt::from_hex_unchecked("0x100000000000000000000000000000000");
        assert!(Claims::decode(&action(too_wide)).is_none());
    }

    #[tokio::test]
    async fn disabled_cosmetics_preserve_ignored_tokens_but_require_the_bound_owner() {
        let checks = SettlementChecks { tag: 11u64.into(), l2: None };
        let action = action(vec![
            11u64.into(),
            99u64.into(),
            123u64.into(),
            Felt::from_hex_unchecked("0xabc"),
            Felt::TWO,
            Felt::ONE,
            19u64.into(),
            999u64.into(),
            Felt::ZERO,
            Felt::ZERO,
        ]);
        assert!(checks.is_settlement(&action));
        assert!(checks
            .verify(&action, &[123u64.into(), Felt::ZERO, Felt::ONE, Felt::ZERO, 1300u64.into()])
            .await
            .unwrap());
        assert!(!checks
            .verify(&action, &[789u64.into(), Felt::ZERO, Felt::ONE, Felt::ZERO, 1300u64.into()])
            .await
            .unwrap());
    }
    #[tokio::test]
    async fn admission_reads_finalized_l2_wallet_ownership_and_retains_original_snapshot() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        };
        struct L2Fixture {
            owner: AtomicU64,
            unavailable: AtomicBool,
            finalized: AtomicBool,
        }
        let source = Arc::new(L2Fixture {
            owner: AtomicU64::new(123),
            unavailable: AtomicBool::new(false),
            finalized: AtomicBool::new(true),
        });
        async fn rpc(State(source): State<Arc<L2Fixture>>, Json(request): Json<Value>) -> Json<Value> {
            if source.unavailable.load(Ordering::SeqCst) {
                return Json(serde_json::json!({"jsonrpc": "2.0", "id": request["id"],
                    "error": {"code": -32603, "message": "upstream unavailable"}}));
            }
            let result = match request["method"].as_str().unwrap() {
                "starknet_getBlockWithTxHashes" => {
                    assert_eq!(request["params"]["block_id"], "l1_accepted");
                    let mut block = finalized_block();
                    if !source.finalized.load(Ordering::SeqCst) {
                        block["status"] = serde_json::json!("ACCEPTED_ON_L2");
                    }
                    block
                }
                "starknet_call" => {
                    assert_eq!(request["params"]["block_id"]["block_hash"], "0xabc");
                    let call = &request["params"]["request"];
                    assert_eq!(call["contract_address"], "0xb");
                    assert_eq!(call["calldata"], serde_json::json!(["0x13", "0x0"]));
                    if call["entry_point_selector"] == get_selector_from_name("owner_of").unwrap().to_hex_string() {
                        serde_json::json!([Felt::from(source.owner.load(Ordering::SeqCst)).to_hex_string()])
                    } else {
                        assert_eq!(
                            call["entry_point_selector"],
                            get_selector_from_name("get_metadata_raw").unwrap().to_hex_string()
                        );
                        serde_json::json!(["0x141"])
                    }
                }
                method => panic!("unexpected RPC method: {method}"),
            };
            Json(serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route("/", post(rpc)).with_state(source.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let checks = SettlementChecks {
            tag: 11u64.into(),
            l2: Some(JsonRpcClient::new(HttpTransport::new(url.parse::<url::Url>().unwrap()))),
        };
        let proposal = action(vec![
            11u64.into(),
            99u64.into(),
            123u64.into(),
            Felt::from_hex_unchecked("0xabc"),
            Felt::TWO,
            Felt::ONE,
            19u64.into(),
            123u64.into(),
            321u64.into(),
            Felt::ZERO,
        ]);
        let policy = [123u64.into(), 11u64.into(), 12u64.into(), 3u64.into(), 1300u64.into()];
        assert!(checks.verify(&proposal, &policy).await.unwrap());
        let mut stale_snapshot = proposal.arguments.clone();
        stale_snapshot[4] = Felt::ONE;
        assert!(!checks.verify(&action(stale_snapshot), &policy).await.unwrap());
        let mut wrong_hash = proposal.arguments.clone();
        wrong_hash[3] = Felt::ONE;
        assert!(!checks.verify(&action(wrong_hash), &policy).await.unwrap());
        source.finalized.store(false, Ordering::SeqCst);
        assert!(checks.verify(&proposal, &policy).await.is_err(), "L2-only acceptance is insufficient");
        source.finalized.store(true, Ordering::SeqCst);
        source.owner.store(456, Ordering::SeqCst);
        assert!(!checks.verify(&proposal, &policy).await.unwrap(), "the gameplay account is not the L2 wallet");
        source.owner.store(123, Ordering::SeqCst);
        let retained = proposal.encode().unwrap();
        source.owner.store(789, Ordering::SeqCst);
        assert!(!checks.verify(&proposal, &policy).await.unwrap());
        let recovered = Intent::decode(&retained).unwrap();
        assert_eq!(recovered, proposal);
        let claims = Claims::decode(&recovered).unwrap();
        assert_eq!(claims.owner, 123u64.into());
        assert_eq!(claims.block_hash, Felt::from_hex_unchecked("0xabc"));
        assert_eq!(claims.block_number, 2);
        assert_eq!(Claims::decode(&recovered).unwrap().tokens[0].attributes, 321);
        source.unavailable.store(true, Ordering::SeqCst);
        assert!(checks.verify(&proposal, &policy).await.is_err(), "an unavailable L2 is not an eligibility rejection");
        source.unavailable.store(false, Ordering::SeqCst);
        source.owner.store(123, Ordering::SeqCst);
        assert!(checks.verify(&proposal, &policy).await.unwrap());
        server.abort();
    }

    #[tokio::test]
    async fn stalled_l2_admission_is_bounded_before_sampling() {
        use axum::{routing::post, Router};
        async fn stalled() -> &'static str {
            std::future::pending().await
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/", post(stalled))).await.unwrap();
        });
        let checks = SettlementChecks {
            tag: 11u64.into(),
            l2: Some(JsonRpcClient::new(HttpTransport::new(url.parse::<url::Url>().unwrap()))),
        };
        let proposal = action(vec![
            11u64.into(),
            99u64.into(),
            123u64.into(),
            Felt::from_hex_unchecked("0xabc"),
            Felt::TWO,
            Felt::ONE,
            19u64.into(),
            123u64.into(),
            321u64.into(),
            Felt::ZERO,
        ]);
        let policy = [123u64.into(), 11u64.into(), 12u64.into(), 3u64.into(), 1300u64.into()];
        let error = tokio::time::timeout(std::time::Duration::from_secs(15), checks.verify(&proposal, &policy))
            .await
            .expect("stalled external source must not block the admission queue")
            .unwrap_err();
        assert!(error.to_string().contains("timed out before acceptance"));
        server.abort();
    }
}
