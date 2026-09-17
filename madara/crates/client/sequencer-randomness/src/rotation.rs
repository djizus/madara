use crate::journal::Journal;
use anyhow::{bail, ensure};
use starknet_accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet_core::{
    types::{
        BlockId, BlockTag, BroadcastedInvokeTransaction, BroadcastedTransaction, Call, DataAvailabilityMode,
        ExecutionResult, Felt, FunctionCall, StarknetError,
    },
    utils::get_selector_from_name,
};
use starknet_providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError};
use starknet_signers::{LocalWallet, SigningKey};
use std::time::Duration;

type Rpc = JsonRpcClient<HttpTransport>;
const HEAD: BlockId = BlockId::Tag(BlockTag::PreConfirmed);

/// Only a binding-authority-signed, single-call key rotation may enter the execution queue.
pub(crate) async fn validate(
    rpc: &Rpc,
    deployment: Felt,
    chain: Felt,
    transaction: &BroadcastedInvokeTransaction,
) -> anyhow::Result<Felt> {
    let (call, hash) = decode(rpc, chain, transaction)?;
    let fields = &transaction.broadcasted_invoke_txn_v3;
    let authentication = rpc
        .call(
            FunctionCall {
                contract_address: deployment,
                entry_point_selector: get_selector_from_name("authentication")?,
                calldata: vec![],
            },
            HEAD,
        )
        .await?;
    let [_, registry, class] = authentication.as_slice() else {
        bail!("malformed authentication configuration");
    };
    ensure!(rpc.get_class_hash_at(HEAD, call.to).await? == *class, "unapproved gameplay account");
    let owner = view(rpc, *registry, "owner_of", vec![call.to]).await?;
    ensure!(
        owner != Felt::ZERO && view(rpc, *registry, "account_of", vec![owner]).await? == call.to,
        "unregistered gameplay account"
    );
    ensure!(view(rpc, call.to, "binding_authority", vec![]).await? == fields.sender_address, "wrong binding authority");
    let key = view(rpc, fields.sender_address, "get_public_key", vec![]).await?;
    ensure!(
        matches!(starknet_crypto::verify(&key, &hash, &fields.signature[0], &fields.signature[1]), Ok(true)),
        "invalid binding authority signature"
    );
    ensure!(rpc.get_nonce(HEAD, fields.sender_address).await? == fields.nonce, "stale binding authority nonce");
    let simulation = rpc.simulate_transaction(HEAD, BroadcastedTransaction::Invoke(transaction.clone()), []).await?;
    if let starknet_core::types::TransactionTrace::Invoke(trace) = simulation.transaction_trace {
        ensure!(
            !matches!(trace.execute_invocation, starknet_core::types::ExecuteInvocation::Reverted(_)),
            "key rotation simulation reverted"
        );
    } else {
        bail!("unexpected rotation simulation trace");
    }
    Ok(hash)
}

fn decode(rpc: &Rpc, chain: Felt, transaction: &BroadcastedInvokeTransaction) -> anyhow::Result<(Call, Felt)> {
    let fields = &transaction.broadcasted_invoke_txn_v3;
    ensure!(
        !fields.is_query
            && transaction.proof.is_none()
            && fields.proof_facts.is_none()
            && fields.paymaster_data.is_empty()
            && fields.account_deployment_data.is_empty()
            && fields.nonce_data_availability_mode == DataAvailabilityMode::L1
            && fields.fee_data_availability_mode == DataAvailabilityMode::L1
            && fields.signature.len() == 2,
        "unsupported rotation transaction"
    );
    let [count, actor, selector, length, key] = fields.calldata.as_slice() else {
        bail!("rotation must be one call");
    };
    ensure!(
        *count == Felt::ONE
            && *length == Felt::ONE
            && *actor != Felt::ZERO
            && *key != Felt::ZERO
            && *selector == get_selector_from_name("rotate_public_key")?,
        "invalid rotation call"
    );
    let call = Call { to: *actor, selector: *selector, calldata: vec![*key] };
    // This account is used only for the SDK's canonical hash calculation. No signing or RPC submission occurs here.
    let account = SingleOwnerAccount::new(
        rpc,
        LocalWallet::from(SigningKey::from_secret_scalar(Felt::ONE)),
        fields.sender_address,
        chain,
        ExecutionEncoding::New,
    );
    let bounds = &fields.resource_bounds;
    let hash = account
        .execute_v3(vec![call.clone()])
        .nonce(fields.nonce)
        .tip(fields.tip)
        .l1_gas(bounds.l1_gas.max_amount)
        .l1_gas_price(bounds.l1_gas.max_price_per_unit)
        .l2_gas(bounds.l2_gas.max_amount)
        .l2_gas_price(bounds.l2_gas.max_price_per_unit)
        .l1_data_gas(bounds.l1_data_gas.max_amount)
        .l1_data_gas_price(bounds.l1_data_gas.max_price_per_unit)
        .prepared()?
        .transaction_hash(false);
    Ok((call, hash))
}

async fn view(rpc: &Rpc, address: Felt, name: &str, calldata: Vec<Felt>) -> anyhow::Result<Felt> {
    let fields = rpc
        .call(
            FunctionCall { contract_address: address, entry_point_selector: get_selector_from_name(name)?, calldata },
            HEAD,
        )
        .await?;
    let [value] = fields.as_slice() else {
        bail!("malformed {name} view");
    };
    Ok(*value)
}

/// Admission stays fenced until the retained transaction has a receipt, including after a restart.
pub(crate) async fn resume(rpc: &Rpc, journal: &Journal, chain: Felt) -> anyhow::Result<Option<(Felt, bool)>> {
    let Some((hash, bytes)) = journal.pending_key_rotation().await? else {
        return Ok(None);
    };
    let transaction: BroadcastedInvokeTransaction = serde_json::from_slice(&bytes)?;
    ensure!(decode(rpc, chain, &transaction)?.1 == hash, "retained rotation hash mismatch");
    loop {
        match rpc.get_transaction_receipt(hash).await {
            Ok(receipt) => {
                ensure!(*receipt.receipt.transaction_hash() == hash, "rotation receipt hash mismatch");
                let success = !matches!(receipt.receipt.execution_result(), ExecutionResult::Reverted { .. });
                journal.finish_key_rotation(hash).await?;
                return Ok(Some((hash, success)));
            }
            Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => {}
            Err(error) => {
                tracing::warn!(target: "sequencer_randomness", %error, "rotation receipt unavailable; retaining admission fence");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        }
        match rpc.add_invoke_transaction(transaction.clone()).await {
            Ok(received) => ensure!(received.transaction_hash == hash, "rotation submission hash mismatch"),
            Err(error) => {
                // Even an invalid nonce can mean the transaction landed while its receipt is unavailable.
                tracing::warn!(target: "sequencer_randomness", %error, "rotation submission unresolved; reconciling");
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn signed_rotation(rpc: &Rpc) -> (BroadcastedInvokeTransaction, Felt, Felt) {
        let secret = Felt::from(12345);
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(secret));
        let account = SingleOwnerAccount::new(rpc, signer, Felt::from(7), Felt::from(9), ExecutionEncoding::New);
        let call = Call {
            to: Felt::from(11),
            selector: get_selector_from_name("rotate_public_key").unwrap(),
            calldata: vec![Felt::from(19)],
        };
        let prepared = account
            .execute_v3(vec![call])
            .nonce(Felt::from(3))
            .tip(0)
            .l1_gas(100)
            .l1_gas_price(10)
            .l2_gas(1_000_000)
            .l2_gas_price(20)
            .l1_data_gas(200)
            .l1_data_gas_price(30)
            .prepared()
            .unwrap();
        (
            prepared.get_invoke_request(false, false).await.unwrap(),
            prepared.transaction_hash(false),
            starknet_crypto::get_public_key(&secret),
        )
    }

    #[tokio::test]
    async fn canonical_rotation_hash_preserves_authority_signature_and_rejects_other_call_shapes() {
        let rpc = Rpc::new(HttpTransport::new("http://127.0.0.1:1".parse::<url::Url>().unwrap()));
        let (transaction, expected, key) = signed_rotation(&rpc).await;
        let (call, hash) = decode(&rpc, Felt::from(9), &transaction).unwrap();
        assert_eq!(hash, expected);
        assert_eq!(call.to, Felt::from(11));
        let signature = &transaction.broadcasted_invoke_txn_v3.signature;
        assert!(starknet_crypto::verify(&key, &hash, &signature[0], &signature[1]).unwrap());
        for index in [1, 4] {
            let mut altered = transaction.clone();
            altered.broadcasted_invoke_txn_v3.calldata[index] += Felt::ONE;
            let (_, hash) = decode(&rpc, Felt::from(9), &altered).unwrap();
            assert!(!starknet_crypto::verify(&key, &hash, &signature[0], &signature[1]).unwrap());
        }
        for index in [0, 2, 3] {
            let mut altered = transaction.clone();
            altered.broadcasted_invoke_txn_v3.calldata[index] += Felt::ONE;
            assert!(decode(&rpc, Felt::from(9), &altered).is_err());
        }
        let mut query = transaction.clone();
        query.broadcasted_invoke_txn_v3.is_query = true;
        assert!(decode(&rpc, Felt::from(9), &query).is_err());
        let mut appended = transaction.clone();
        appended.broadcasted_invoke_txn_v3.calldata.push(Felt::ONE);
        assert!(decode(&rpc, Felt::from(9), &appended).is_err());
        let mut zero_key = transaction;
        zero_key.broadcasted_invoke_txn_v3.calldata[4] = Felt::ZERO;
        assert!(decode(&rpc, Felt::from(9), &zero_key).is_err());
    }
}
