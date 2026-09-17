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
        "backwards execution time",
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

/// Outcomes are authenticated by the retained transaction and the season emitter, then
/// folded into the same binding-dependent state commitment as the contract.
pub(crate) fn receipt_outcome(
    record: &Record,
    receipt: &starknet_core::types::TransactionReceipt,
) -> anyhow::Result<Option<(ChainProgress, bool)>> {
    use starknet_core::{types::Felt, utils::get_selector_from_name};
    use starknet_types_core::hash::{Poseidon, StarkHash};
    if matches!(receipt.execution_result(), ExecutionResult::Reverted { .. }) {
        return Ok(None);
    }
    let prefix = [get_selector_from_name("RecordingEvent")?, get_selector_from_name("ExecutionRecorded")?];
    let mut events =
        receipt.events().iter().filter(|event| event.from_address == record.intent.deployment && event.keys == prefix);
    let Some(event) = events.next() else {
        anyhow::bail!("successful recorded transaction has no execution event");
    };
    if events.next().is_some() {
        anyhow::bail!("duplicate execution event");
    }
    let [game, actor, nonce, consumed, order, status, reason] = event.data.as_slice() else {
        anyhow::bail!("malformed execution event");
    };
    if *game != record.intent.game
        || *actor != record.intent.actor
        || *nonce != Felt::from(record.intent.nonce)
        || *order != Felt::from(record.envelope.order)
        || (*consumed != Felt::ZERO && *consumed != Felt::ONE)
        || !((*status == Felt::ONE && *reason == Felt::ZERO) || (*status == Felt::TWO && *reason != Felt::ZERO))
    {
        anyhow::bail!("execution event does not match accepted ticket");
    }
    let binding = record.envelope.binding()?;
    let state = Poseidon::hash_array(&[record.envelope.preceding_state, binding, *status, *reason, *consumed]);
    Ok(Some((
        ChainProgress {
            order: record.envelope.order,
            binding,
            state,
            result: if *status == Felt::TWO { *reason } else { state },
        },
        *status == Felt::TWO,
    )))
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

    fn receipt(record: &Record, status: u64, reason: Felt, consumed: bool) -> starknet_core::types::TransactionReceipt {
        use starknet_core::utils::get_selector_from_name;
        serde_json::from_value(serde_json::json!({
            "type": "INVOKE", "transaction_hash": "0x1", "actual_fee": {"amount":"0x0", "unit":"FRI"},
            "finality_status":"ACCEPTED_ON_L2", "execution_status":"SUCCEEDED", "messages_sent":[],
            "execution_resources":{"l1_gas":0,"l1_data_gas":0,"l2_gas":0},
            "events":[{"from_address":record.intent.deployment,
                "keys":[get_selector_from_name("RecordingEvent").unwrap(),get_selector_from_name("ExecutionRecorded").unwrap()],
                "data":[record.intent.game,record.intent.actor,Felt::from(record.intent.nonce),
                    Felt::from(u64::from(consumed)),Felt::from(record.envelope.order),Felt::from(status),reason]}]
        })).unwrap()
    }

    #[test]
    fn receipt_outcome_matches_ticket_and_binds_root_state_and_consumption() {
        let record = record(1);
        let event = receipt(&record, 1, Felt::ZERO, true);
        let (success, rejected) = receipt_outcome(&record, &event).unwrap().unwrap();
        assert!(!rejected);
        assert_eq!(success.binding, record.envelope.binding().unwrap());
        assert_eq!(success.result, success.state);
        let failed = receipt(&record, 2, Felt::from_bytes_be_slice(b"STALE_NONCE"), false);
        let (failure, rejected) = receipt_outcome(&record, &failed).unwrap().unwrap();
        assert!(rejected);
        assert_eq!(failure.result, Felt::from_bytes_be_slice(b"STALE_NONCE"));
        assert_ne!(failure.state, success.state);
        let consumed_failure = receipt(&record, 2, failure.result, true);
        assert_ne!(receipt_outcome(&record, &consumed_failure).unwrap().unwrap().0.state, failure.state);
        let mut changed_root = self::record(1);
        changed_root.envelope.root[0] ^= 1;
        assert_ne!(receipt_outcome(&changed_root, &event).unwrap().unwrap().0.state, success.state);
        let mut changed_state = self::record(1);
        changed_state.envelope.preceding_state += Felt::ONE;
        assert_ne!(receipt_outcome(&changed_state, &event).unwrap().unwrap().0.state, success.state);
    }

    #[test]
    fn malformed_foreign_duplicate_and_mismatched_execution_events_are_rejected() {
        let record = record(1);
        for case in 0..8 {
            let mut event = receipt(&record, 1, Felt::ZERO, true);
            let starknet_core::types::TransactionReceipt::Invoke(ref mut invoke) = event else { unreachable!() };
            match case {
                0 => invoke.events[0].from_address += Felt::ONE,
                1 => invoke.events.push(invoke.events[0].clone()),
                2 => invoke.events[0].data[0] += Felt::ONE,
                3 => invoke.events[0].data[1] += Felt::ONE,
                4 => invoke.events[0].data[2] += Felt::ONE,
                5 => invoke.events[0].data[3] = Felt::TWO,
                6 => invoke.events[0].data[4] += Felt::ONE,
                _ => {
                    invoke.events[0].data.pop();
                }
            }
            assert!(receipt_outcome(&record, &event).is_err());
        }
        assert!(receipt_outcome(&record, &receipt(&record, 1, Felt::ONE, true)).is_err());
        assert!(receipt_outcome(&record, &receipt(&record, 2, Felt::ZERO, true)).is_err());
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
