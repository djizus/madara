use crate::util::BatchToExecute;
use mc_exec::execution::TxInfo;
use mc_sequencer_randomness::submission::ExecutionObservers;

pub(crate) fn observe_batch(observers: &ExecutionObservers, batch: &mut BatchToExecute) {
    for (transaction, info) in batch.txs.iter().zip(batch.additional_info.iter_mut()) {
        info.refusal_reporter = observers.reporter(transaction.tx_hash().0);
    }
}
