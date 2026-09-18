use crate::{
    admission::AdmissionSlots,
    node::{Execution, Node},
};
use anyhow::{ensure, Context};
use mp_convert::ToFelt;
use mp_receipt::ExecutionResult;
use mp_rpc::v0_10_2::BroadcastedInvokeTxn;
use mp_transactions::InvokeTransactionV3;
use starknet_core::utils::get_selector_from_name;
use starknet_types_core::felt::Felt;

/// The binding authority signs the normal account transaction. Only its actor waits;
/// unrelated gameplay keeps running and Madara performs final transaction validation.
pub(crate) async fn submit(
    node: &Node,
    slots: &AdmissionSlots,
    transaction: BroadcastedInvokeTxn,
) -> anyhow::Result<Felt> {
    let Rotation { actor, authority, nonce, hash, signature } =
        decode(&transaction, node.backend.chain_config().chain_id.clone().to_felt())?;
    let authentication = node.world_view("authentication", vec![]).await?;
    let [_, registry, class] = authentication.as_slice() else {
        anyhow::bail!("malformed authentication configuration")
    };
    ensure!(
        node.backend.view_on_latest().get_contract_class_hash(&actor)? == Some(*class),
        "unapproved gameplay account"
    );
    let owner = scalar(node, *registry, "owner_of", vec![actor]).await?;
    ensure!(
        owner != Felt::ZERO && scalar(node, *registry, "account_of", vec![owner]).await? == actor,
        "unregistered gameplay account"
    );
    ensure!(scalar(node, actor, "binding_authority", vec![]).await? == authority, "wrong binding authority");
    let key = scalar(node, authority, "get_public_key", vec![]).await?;
    ensure!(
        matches!(starknet_crypto::verify(&key, &hash, &signature[0], &signature[1]), Ok(true)),
        "invalid binding authority signature"
    );
    ensure!(nonce == node.nonce(authority)?, "rotation requires the current binding authority nonce");
    let _permit = slots.rotation(actor).await?;
    match node.execute(hash, transaction).await? {
        Execution::Included(receipt) => {
            ensure!(receipt.execution_result() == ExecutionResult::Succeeded, "gameplay key rotation reverted");
            Ok(hash)
        }
        Execution::Refused(reason) => anyhow::bail!("gameplay key rotation refused: {reason}"),
    }
}

struct Rotation {
    actor: Felt,
    authority: Felt,
    nonce: Felt,
    hash: Felt,
    signature: [Felt; 2],
}

fn decode(transaction: &BroadcastedInvokeTxn, chain: Felt) -> anyhow::Result<Rotation> {
    let BroadcastedInvokeTxn::V3(transaction) = transaction else { anyhow::bail!("rotation requires an invoke v3") };
    ensure!(transaction.proof.is_none() && transaction.proof_facts.is_none(), "rotation cannot carry proofs");
    let tx = InvokeTransactionV3::from(transaction.clone());
    let [count, actor, selector, length, key] = tx.calldata.as_slice() else {
        anyhow::bail!("rotation must contain exactly one call")
    };
    ensure!(
        *count == Felt::ONE
            && *length == Felt::ONE
            && *actor != Felt::ZERO
            && *key != Felt::ZERO
            && *selector == get_selector_from_name("rotate_public_key")?,
        "invalid rotation call"
    );
    ensure!(tx.paymaster_data.is_empty() && tx.account_deployment_data.is_empty(), "unsupported rotation transaction");
    let signature = tx.signature.as_slice().try_into().context("rotation requires two signature felts")?;
    Ok(Rotation {
        actor: *actor,
        authority: tx.sender_address,
        nonce: tx.nonce,
        hash: tx.compute_hash(chain, false),
        signature,
    })
}

async fn scalar(node: &Node, contract: Felt, name: &'static str, args: Vec<Felt>) -> anyhow::Result<Felt> {
    let values = node.view(contract, name, args).await?;
    let [value] = values.as_slice() else { anyhow::bail!("malformed {name} view") };
    Ok(*value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp_rpc::v0_10_2::BroadcastedInvokeTxnV3;
    use starknet_signers::SigningKey;
    use std::sync::Arc;

    #[test]
    fn rotation_preserves_the_authority_signed_hash_and_rejects_extra_calls() {
        let key = SigningKey::from_secret_scalar(Felt::from(123));
        let mut tx = InvokeTransactionV3 {
            sender_address: Felt::from(7),
            nonce: Felt::from(3),
            resource_bounds: mp_transactions::ResourceBoundsMapping {
                l1_data_gas: Some(Default::default()),
                ..Default::default()
            },
            calldata: Arc::new(vec![
                Felt::ONE,
                Felt::from(11),
                get_selector_from_name("rotate_public_key").unwrap(),
                Felt::ONE,
                Felt::from(19),
            ]),
            ..Default::default()
        };
        let identity = tx.compute_hash(Felt::from(9), false);
        let sig = key.sign(&identity).unwrap();
        tx.signature = Arc::new(vec![sig.r, sig.s]);
        let rpc = tx.to_rpc_v0_10_2();
        let mut broadcast =
            BroadcastedInvokeTxn::V3(BroadcastedInvokeTxnV3 { inner: rpc.inner, proof: None, proof_facts: None });
        let Rotation { actor, authority, nonce, hash, signature } = decode(&broadcast, Felt::from(9)).unwrap();
        assert_eq!((actor, authority, hash), (Felt::from(11), Felt::from(7), identity));
        assert_eq!(nonce, Felt::from(3));
        assert!(starknet_crypto::verify(&key.verifying_key().scalar(), &hash, &signature[0], &signature[1]).unwrap());
        if let BroadcastedInvokeTxn::V3(ref mut fields) = broadcast {
            Arc::make_mut(&mut fields.inner.calldata).push(Felt::ONE);
        }
        assert!(decode(&broadcast, Felt::from(9)).is_err());
    }
}
