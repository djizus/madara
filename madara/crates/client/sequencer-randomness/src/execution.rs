use crate::{
    journal::{ChainProgress, Record},
    submission::SubmissionKind,
};
use starknet_core::types::{ContractExecutionError, ExecutionResult, StarknetError, TransactionStatus};
use starknet_providers::ProviderError;
use std::{future::Future, time::Duration};

pub(crate) enum Attempt {
    Pending,
    Failed,
}

pub(crate) enum Observation {
    Recorded(ChainProgress, bool),
    Unexecuted,
    Stale,
}

pub(crate) trait ExecutionIo: Sync {
    fn outcome(&self, record: &Record) -> impl Future<Output = anyhow::Result<Observation>> + Send;
    fn attempt(&self, record: &Record, kind: SubmissionKind) -> impl Future<Output = anyhow::Result<Attempt>> + Send;
    fn complete(
        &self,
        record: &Record,
        progress: ChainProgress,
        rejected: bool,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

// Every retry reconciles before broadcasting. Neither transport errors nor elapsed time
// authorize a rejection, and the accepted record is never reconstructed or resampled.
pub(crate) async fn execute(io: &impl ExecutionIo, record: &Record) -> anyhow::Result<()> {
    let mut kind = SubmissionKind::Execute;
    loop {
        match tokio::time::timeout(Duration::from_secs(30), advance(io, record, kind)).await {
            Ok(Ok(Some(next))) => kind = next,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) if error.downcast_ref::<ProviderError>().is_some() => {
                tracing::warn!(target: "sequencer_randomness", order = record.envelope.order,
                    %error, "execution transport unavailable; reconciling retained ticket");
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => tracing::warn!(target: "sequencer_randomness", order = record.envelope.order,
                "execution observation timed out; reconciling retained ticket"),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn advance(
    io: &impl ExecutionIo,
    record: &Record,
    kind: SubmissionKind,
) -> anyhow::Result<Option<SubmissionKind>> {
    match io.outcome(record).await? {
        Observation::Recorded(progress, rejected) => {
            io.complete(record, progress, rejected).await?;
            return Ok(None);
        }
        Observation::Stale => return Ok(Some(kind)),
        Observation::Unexecuted => {}
    }
    let next = match io.attempt(record, kind).await? {
        Attempt::Pending => kind,
        Attempt::Failed => SubmissionKind::Reject,
    };
    Ok(Some(next))
}

pub(crate) fn included_failure(status: &TransactionStatus) -> bool {
    match status {
        TransactionStatus::AcceptedOnL2(ExecutionResult::Reverted { reason })
        | TransactionStatus::AcceptedOnL1(ExecutionResult::Reverted { reason }) => !authentication_revert(reason),
        _ => false,
    }
}

fn authentication_revert(reason: &str) -> bool {
    [
        "out of order",
        "binding predecessor mismatch",
        "state predecessor mismatch",
        "altered action",
        "only sequencing submitter",
        "invalid transaction context",
        "stale authority",
        "invalid authority signature",
        "recorded resource bounds mismatch",
        "execution config mismatch",
        "future execution time",
        "malformed envelope",
        "invalid player signature",
        "invalid acceptance",
    ]
    .iter()
    .any(|message| reason.contains(message))
}

// Only explicit execution-limit refusals are final. Nonce, admission, transport and
// unknown errors remain retryable; an RPC error string alone is not evidence of execution.
pub(crate) fn deterministic_refusal(error: &ProviderError) -> bool {
    let ProviderError::StarknetError(StarknetError::TransactionExecutionError(data)) = error else {
        return false;
    };
    let mut frame = &data.execution_error;
    while let ContractExecutionError::Nested(inner) = frame {
        frame = &inner.error;
    }
    let ContractExecutionError::Message(reason) = frame else { unreachable!() };
    deterministic_limit(reason)
}

pub(crate) fn deterministic_limit(reason: &str) -> bool {
    limit_reason(reason).is_some()
}

pub(crate) fn limit_reason(reason: &str) -> Option<&'static str> {
    if authentication_revert(reason) {
        return None;
    }
    ["Exceeded the maximum number of events,", "Exceeded the maximum data length,", "Exceeded the maximum keys length,"]
        .into_iter()
        .find(|message| reason.contains(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::Authorization,
        protocol::{Envelope, Intent},
        ticket::State,
    };
    use starknet_core::types::{Felt, TransactionExecutionErrorData};
    use std::{collections::HashMap, sync::Mutex};

    #[derive(Clone, Copy)]
    enum Failure {
        IncludedRevert,
        ReceiptLostAfterExecution,
        ReceiptLostBeforeExecution,
        DeterministicRefusal,
    }

    struct Chain {
        failure: Failure,
        calls: Vec<(u64, SubmissionKind, Envelope)>,
        outcomes: HashMap<u64, (ChainProgress, bool)>,
        adopted: Vec<(u64, bool)>,
        gameplay_executions: usize,
    }

    fn record(order: u64) -> Record {
        let intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::TWO,
            game: Felt::THREE,
            actor: Felt::ONE,
            nonce: order - 1,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 1000,
            valid_until: 1010,
            last_order: 10,
            arguments: vec![Felt::ONE],
        };
        Record {
            envelope: Envelope {
                action: intent.identity().unwrap(),
                order,
                predecessor: Felt::ZERO,
                preceding_state: Felt::ZERO,
                timestamp: 1005,
                execution_config: Felt::ONE,
                l2_gas: 1_200_000_000,
                root: [197; 32],
            },
            intent,
            authorization: Authorization { public_key: Felt::ONE, r: Felt::TWO, s: Felt::THREE },
            result: None,
            following_state: None,
            rejected: None,
            state: State::Committed,
        }
    }

    impl ExecutionIo for Mutex<Chain> {
        async fn outcome(&self, record: &Record) -> anyhow::Result<Observation> {
            Ok(match self.lock().unwrap().outcomes.get(&record.envelope.order) {
                Some((progress, rejected)) => Observation::Recorded(*progress, *rejected),
                None => Observation::Unexecuted,
            })
        }

        async fn attempt(&self, record: &Record, kind: SubmissionKind) -> anyhow::Result<Attempt> {
            let mut chain = self.lock().unwrap();
            let first = chain.calls.is_empty();
            chain.calls.push((record.envelope.order, kind, record.envelope.clone()));
            if first {
                match chain.failure {
                    Failure::IncludedRevert => {
                        assert!(included_failure(&TransactionStatus::AcceptedOnL2(ExecutionResult::Reverted {
                            reason: "Out of gas".into(),
                        })));
                        return Ok(Attempt::Failed);
                    }
                    Failure::DeterministicRefusal => {
                        assert!(deterministic_refusal(&limit_error()));
                        return Ok(Attempt::Failed);
                    }
                    Failure::ReceiptLostBeforeExecution => return Err(ProviderError::RateLimited.into()),
                    Failure::ReceiptLostAfterExecution => {}
                }
            }
            let rejected = kind == SubmissionKind::Reject;
            if !rejected {
                chain.gameplay_executions += 1;
            }
            let result = if rejected { Felt::from_bytes_be_slice(b"EXECUTION_FAILED") } else { Felt::from(99) };
            chain.outcomes.insert(
                record.envelope.order,
                (
                    ChainProgress {
                        order: record.envelope.order,
                        binding: record.envelope.binding().unwrap(),
                        state: Felt::from(71),
                        result,
                    },
                    rejected,
                ),
            );
            if first && matches!(chain.failure, Failure::ReceiptLostAfterExecution) {
                return Err(ProviderError::RateLimited.into());
            }
            Ok(Attempt::Pending)
        }

        async fn complete(&self, record: &Record, progress: ChainProgress, rejected: bool) -> anyhow::Result<()> {
            assert_eq!(progress.binding, record.envelope.binding().unwrap());
            self.lock().unwrap().adopted.push((progress.order, rejected));
            Ok(())
        }
    }

    async fn run(failure: Failure) -> Chain {
        let io = Mutex::new(Chain {
            failure,
            calls: vec![],
            outcomes: HashMap::new(),
            adopted: vec![],
            gameplay_executions: 0,
        });
        tokio::time::timeout(Duration::from_secs(2), execute(&io, &record(1))).await.unwrap().unwrap();
        execute(&io, &record(2)).await.unwrap();
        let chain = io.into_inner().unwrap();
        for (order, _, envelope) in &chain.calls {
            assert!(envelope == &record(*order).envelope);
        }
        chain
    }

    #[tokio::test]
    async fn included_revert_records_rejection_then_executes_next_ticket() {
        let chain = run(Failure::IncludedRevert).await;
        assert_eq!(chain.adopted, vec![(1, true), (2, false)]);
        assert_eq!(chain.gameplay_executions, 1);
        assert_eq!(chain.calls[1].1, SubmissionKind::Reject);
        assert_eq!(chain.outcomes[&1].0.result, Felt::from_bytes_be_slice(b"EXECUTION_FAILED"));
    }

    #[tokio::test]
    async fn lost_receipt_after_execution_adopts_without_duplicate_or_rejection() {
        let chain = run(Failure::ReceiptLostAfterExecution).await;
        assert_eq!(chain.adopted, vec![(1, false), (2, false)]);
        assert_eq!(chain.calls.len(), 2);
        assert_eq!(chain.gameplay_executions, 2);
    }

    #[tokio::test]
    async fn lost_receipt_before_execution_replays_once_with_original_root_and_time() {
        let chain = run(Failure::ReceiptLostBeforeExecution).await;
        assert_eq!(chain.adopted, vec![(1, false), (2, false)]);
        assert_eq!(chain.calls.iter().filter(|(order, _, _)| *order == 1).count(), 2);
        assert_eq!(chain.gameplay_executions, 2);
        assert!(chain.calls.iter().all(|(_, kind, _)| *kind == SubmissionKind::Execute));
    }

    #[tokio::test]
    async fn deterministic_refusal_records_rejection_then_executes_next_ticket() {
        let chain = run(Failure::DeterministicRefusal).await;
        assert_eq!(chain.adopted, vec![(1, true), (2, false)]);
    }

    fn limit_error() -> ProviderError {
        ProviderError::StarknetError(StarknetError::TransactionExecutionError(TransactionExecutionErrorData {
            transaction_index: 0,
            execution_error: ContractExecutionError::Message(
                "Exceeded the maximum data length, data length: 301, max data length: 300.".into(),
            ),
        }))
    }

    #[test]
    fn authentication_and_unconfirmed_reverts_never_authorize_rejection() {
        for reason in ["out of order", "binding predecessor mismatch", "state predecessor mismatch", "stale authority"]
        {
            assert!(!included_failure(&TransactionStatus::AcceptedOnL2(ExecutionResult::Reverted {
                reason: reason.into()
            })));
        }
        assert!(!included_failure(&TransactionStatus::PreConfirmed(ExecutionResult::Reverted {
            reason: "Out of gas".into()
        })));
        for error in [
            ProviderError::RateLimited,
            ProviderError::StarknetError(StarknetError::TransactionHashNotFound),
            ProviderError::StarknetError(StarknetError::InvalidTransactionNonce("nonce".into())),
            ProviderError::StarknetError(StarknetError::FailedToReceiveTransaction),
        ] {
            assert!(!deterministic_refusal(&error));
        }
    }
}
