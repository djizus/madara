use crate::util::BatchToExecute;
use anyhow::bail;
use blockifier::transaction::transaction_execution::Transaction;
use mc_sequencer_randomness::submission::SubmissionGate;
use starknet_api::executable_transaction::AccountTransaction;

pub(super) async fn authorize_batch(gate: &mut SubmissionGate, batch: &mut BatchToExecute) -> anyhow::Result<()> {
    for (transaction, info) in batch.txs.iter().zip(batch.additional_info.iter_mut()) {
        if *transaction.sender_address().0.key() != gate.account {
            continue;
        }
        let Transaction::Account(account) = transaction else {
            bail!("sequencing authority requires an ordinary account transaction");
        };
        let AccountTransaction::Invoke(invoke) = &account.tx else {
            bail!("sequencing authority requires a native execute invocation");
        };
        gate.authorize(
            invoke.tx_hash.0,
            &invoke.calldata().0,
            account.resource_bounds().get_l2_bounds().max_amount.0,
            account.execution_flags.only_query,
        )
        .await?;
        info.refusal_reporter = Some(gate.refusal_reporter(invoke.tx_hash.0));
    }
    Ok(())
}
