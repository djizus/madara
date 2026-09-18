use crate::{
    admission::Permit,
    node::{Execution, Node},
    ticket::{ActionStatus, RecordedTicket},
};
use anyhow::{ensure, Context};
use mp_receipt::{ExecutionResult, TransactionReceipt};
use mp_rpc::v0_10_2::BroadcastedInvokeTxn;
use starknet_core::utils::get_selector_from_name;
use starknet_types_core::felt::Felt;
use std::{collections::VecDeque, ops::Range, sync::Arc, time::Duration};

pub(crate) struct PendingTicket {
    pub record: RecordedTicket,
    pub permit: Permit,
}

#[async_trait::async_trait]
pub(crate) trait ExecutionNode: Send + Sync {
    fn deployment(&self) -> Felt;
    fn prepare(
        &self,
        to: Felt,
        selector: &'static str,
        payload: Vec<Felt>,
    ) -> anyhow::Result<(Felt, BroadcastedInvokeTxn)>;
    async fn execute(&self, hash: Felt, transaction: BroadcastedInvokeTxn) -> anyhow::Result<Execution>;
    fn receipt(&self, hash: Felt) -> anyhow::Result<Option<TransactionReceipt>>;
    async fn head_order(&self) -> anyhow::Result<u64>;
    async fn wait_for_state_change(&self);
}

#[async_trait::async_trait]
impl ExecutionNode for Node {
    fn deployment(&self) -> Felt {
        self.deployment
    }
    fn prepare(
        &self,
        to: Felt,
        selector: &'static str,
        payload: Vec<Felt>,
    ) -> anyhow::Result<(Felt, BroadcastedInvokeTxn)> {
        Node::prepare(self, to, selector, payload)
    }
    async fn execute(&self, hash: Felt, transaction: BroadcastedInvokeTxn) -> anyhow::Result<Execution> {
        Node::execute(self, hash, transaction).await
    }
    fn receipt(&self, hash: Felt) -> anyhow::Result<Option<TransactionReceipt>> {
        Node::receipt(self, hash)
    }
    async fn head_order(&self) -> anyhow::Result<u64> {
        Ok(self.head().await?.0)
    }
    async fn wait_for_state_change(&self) {
        let mut tip = self.backend.watch_chain_tip();
        tokio::time::timeout(Duration::from_secs(5), tip.recv()).await.ok();
    }
}

// Only deterministic executor limits authorize rejection before inclusion. A missing
// receipt or an account/order mismatch requires reconciliation, never rejection.
pub(crate) fn deterministic_limit(reason: &str) -> bool {
    ["Exceeded the maximum number of events,", "Exceeded the maximum data length,", "Exceeded the maximum keys length,"]
        .iter()
        .any(|message| reason.contains(message))
}

fn authentication_revert(reason: &str) -> bool {
    [
        "out of order",
        "only sequencing submitter",
        "invalid authority signature",
        "execution config mismatch",
        "future execution time",
        "backwards execution time",
        "malformed envelope",
        "invalid acceptance",
        "order outside randomness epoch",
        "revealed epoch cannot execute",
    ]
    .iter()
    .any(|message| reason.contains(message))
}

/// A failed batch is bisected in order. Only a single definitively failed ticket is
/// rejected; successful siblings execute normally, retaining their original contexts.
pub(crate) async fn execute(node: Arc<impl ExecutionNode>, tickets: Vec<PendingTicket>) -> anyhow::Result<()> {
    let mut batches = VecDeque::from_iter(std::iter::once(0..tickets.len()));
    while let Some(range) = batches.pop_front() {
        let selected = &tickets[range.clone()];
        if execute_range(node.as_ref(), selected, false).await? {
            continue;
        }
        if range.len() > 1 {
            split_front(&mut batches, range);
        } else {
            ensure!(execute_range(node.as_ref(), selected, true).await?, "terminal rejection failed to record");
        }
    }
    Ok(())
}

fn split_front(batches: &mut VecDeque<Range<usize>>, range: Range<usize>) {
    let mid = range.start + range.len() / 2;
    batches.push_front(mid..range.end);
    batches.push_front(range.start..mid);
}

async fn execute_range(node: &impl ExecutionNode, tickets: &[PendingTicket], rejection: bool) -> anyhow::Result<bool> {
    let payload = batch_calldata(tickets.iter().map(|ticket| &ticket.record), rejection)?;
    let selector = if rejection { "reject_execution" } else { "execute_batch" };
    // A transient retry resubmits the exact transaction. Only a proven failed
    // batch creates new transactions when bisected or terminally rejected.
    let (hash, transaction) = node.prepare(node.deployment(), selector, payload)?;
    for attempt in 0..3 {
        for ticket in tickets {
            ticket.permit.resolve(ActionStatus::Submitted {
                action: ticket.record.envelope.action,
                order: ticket.record.envelope.order,
                transaction_hash: hash,
            });
        }
        let result = tokio::time::timeout(Duration::from_secs(30), node.execute(hash, transaction.clone())).await;
        let observed = match result {
            Ok(Ok(outcome)) => Some(outcome),
            other => {
                tracing::warn!(target: "sequencer_randomness", %hash, attempt, error = %match other { Ok(Err(error)) => error.to_string(), Err(error) => error.to_string(), _ => unreachable!() },
                    "submission requires reconciliation");
                node.receipt(hash)?.map(|receipt| Execution::Included(Box::new(receipt)))
            }
        };
        match observed {
            Some(Execution::Included(receipt)) => match receipt.execution_result() {
                ExecutionResult::Succeeded => {
                    let outcomes = receipt_outcomes(tickets.iter().map(|ticket| &ticket.record), hash, &receipt)?;
                    for (ticket, outcome) in tickets.iter().zip(outcomes) {
                        ticket.permit.resolve(outcome);
                    }
                    return Ok(true);
                }
                ExecutionResult::Reverted { reason } if !authentication_revert(&reason) => return Ok(false),
                ExecutionResult::Reverted { .. } => {}
            },
            Some(Execution::Refused(reason)) if deterministic_limit(&reason) => return Ok(false),
            _ => {}
        }
        let head = node.head_order().await?;
        ensure!(
            head < tickets[0].record.envelope.order,
            "head already covers pending ticket but its matching receipt is unavailable"
        );
        // Wait for node state to move after a transient refusal, not a receipt poll.
        node.wait_for_state_change().await;
    }
    anyhow::bail!("game submission paused after three unresolved attempts; node state remains authoritative")
}

fn batch_calldata<'a>(tickets: impl Iterator<Item = &'a RecordedTicket>, rejection: bool) -> anyhow::Result<Vec<Felt>> {
    let tickets: Vec<_> = tickets.collect();
    ensure!(!tickets.is_empty() && tickets.len() <= 64, "invalid execution batch size");
    ensure!(!rejection || tickets.len() == 1, "only a single ticket can be rejected");
    let mut fields = if rejection { vec![] } else { vec![Felt::from(tickets.len() as u64)] };
    for ticket in tickets {
        fields.extend(ticket.calldata()?);
    }
    Ok(fields)
}

pub(crate) fn receipt_outcomes<'a>(
    tickets: impl Iterator<Item = &'a RecordedTicket>,
    hash: Felt,
    receipt: &TransactionReceipt,
) -> anyhow::Result<Vec<ActionStatus>> {
    let prefix = [get_selector_from_name("RecordingEvent")?, get_selector_from_name("ExecutionRecorded")?];
    let tickets: Vec<_> = tickets.collect();
    let emitter = tickets.first().context("empty receipt attribution")?.intent.deployment;
    let events: Vec<_> =
        receipt.events().iter().filter(|event| event.from_address == emitter && event.keys == prefix).collect();
    ensure!(events.len() == tickets.len(), "execution receipt ticket count mismatch");
    tickets
        .into_iter()
        .zip(events)
        .map(|(ticket, event)| {
            let [game, actor, nonce, consumed, order, status, reason] = event.data.as_slice() else {
                anyhow::bail!("malformed execution event");
            };
            ensure!(
                *game == ticket.intent.game
                    && *actor == ticket.intent.actor
                    && *nonce == Felt::from(ticket.intent.nonce)
                    && *order == Felt::from(ticket.envelope.order),
                "execution event does not match submitted ticket"
            );
            ensure!(
                [Felt::ZERO, Felt::ONE].contains(consumed) && [Felt::ONE, Felt::TWO].contains(status),
                "invalid execution result"
            );
            Ok(ActionStatus::Recorded {
                action: ticket.envelope.action,
                order: ticket.envelope.order,
                transaction_hash: hash,
                succeeded: *status == Felt::ONE,
                reason: *reason,
                nonce_consumed: *consumed == Felt::ONE,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::{AdmissionSlots, Slot},
        protocol::{Envelope, Intent},
    };
    use mp_receipt::{Event, InvokeTransactionReceipt};
    use mp_rpc::v0_10_2::BroadcastedInvokeTxnV3;
    use mp_transactions::InvokeTransactionV3;
    use std::{collections::HashMap, sync::Mutex};
    use tokio::sync::watch;

    #[derive(Clone, Copy)]
    enum FirstSubmission {
        Normal,
        LostAfterExecution,
        LostBeforeExecution,
        DeterministicRefusal,
    }
    struct Prepared {
        selector: &'static str,
        payload: Vec<Felt>,
        orders: Vec<u64>,
    }
    struct State {
        prepared: Vec<Prepared>,
        submitted: Vec<Felt>,
        receipts: HashMap<Felt, TransactionReceipt>,
        head: u64,
        effects: Vec<u64>,
    }
    struct TestNode {
        tickets: Vec<RecordedTicket>,
        poison: Option<u64>,
        first: FirstSubmission,
        state: Mutex<State>,
    }
    impl TestNode {
        fn new(tickets: Vec<RecordedTicket>, poison: Option<u64>, first: FirstSubmission) -> Self {
            Self {
                tickets,
                poison,
                first,
                state: Mutex::new(State {
                    prepared: vec![],
                    submitted: vec![],
                    receipts: HashMap::new(),
                    head: 0,
                    effects: vec![],
                }),
            }
        }
        fn included(&self, state: &mut State, hash: Felt, orders: &[u64], rejection: bool) -> TransactionReceipt {
            let reverted = !rejection && orders.iter().any(|order| Some(*order) == self.poison);
            let mut receipt = InvokeTransactionReceipt { transaction_hash: hash, ..Default::default() };
            if reverted {
                receipt.execution_result = ExecutionResult::Reverted { reason: "Out of gas".into() };
            } else {
                for order in orders {
                    assert_eq!(*order, state.head + 1);
                    let ticket = &self.tickets[*order as usize - 1];
                    receipt.events.push(Event {
                        from_address: ticket.intent.deployment,
                        keys: vec![
                            get_selector_from_name("RecordingEvent").unwrap(),
                            get_selector_from_name("ExecutionRecorded").unwrap(),
                        ],
                        data: vec![
                            ticket.intent.game,
                            ticket.intent.actor,
                            ticket.intent.nonce.into(),
                            Felt::ONE,
                            (*order).into(),
                            if rejection { Felt::TWO } else { Felt::ONE },
                            if rejection { Felt::from(99) } else { Felt::ZERO },
                        ],
                    });
                    state.head = *order;
                    if !rejection {
                        state.effects.push(*order);
                    }
                }
            }
            let receipt = TransactionReceipt::Invoke(receipt);
            state.receipts.insert(hash, receipt.clone());
            receipt
        }
    }
    #[async_trait::async_trait]
    impl ExecutionNode for TestNode {
        fn deployment(&self) -> Felt {
            Felt::TWO
        }
        fn prepare(
            &self,
            _: Felt,
            selector: &'static str,
            payload: Vec<Felt>,
        ) -> anyhow::Result<(Felt, BroadcastedInvokeTxn)> {
            let mut state = self.state.lock().unwrap();
            let orders = self
                .tickets
                .iter()
                .filter_map(|ticket| {
                    let fields = ticket.calldata().unwrap();
                    payload.windows(fields.len()).any(|window| window == fields).then_some(ticket.envelope.order)
                })
                .collect::<Vec<_>>();
            assert!(!orders.is_empty());
            state.prepared.push(Prepared { selector, payload, orders });
            let rpc = InvokeTransactionV3::default().to_rpc_v0_10_2();
            Ok((
                Felt::from(state.prepared.len() as u64),
                BroadcastedInvokeTxn::V3(BroadcastedInvokeTxnV3 { inner: rpc.inner, proof: None, proof_facts: None }),
            ))
        }
        async fn execute(&self, hash: Felt, _: BroadcastedInvokeTxn) -> anyhow::Result<Execution> {
            let mut state = self.state.lock().unwrap();
            state.submitted.push(hash);
            if let Some(receipt) = state.receipts.get(&hash) {
                return Ok(Execution::Included(Box::new(receipt.clone())));
            }
            let index = usize::try_from(hash).unwrap() - 1;
            let orders = state.prepared[index].orders.clone();
            let rejection = state.prepared[index].selector == "reject_execution";
            if state.submitted.len() == 1 {
                match self.first {
                    FirstSubmission::LostAfterExecution => {
                        self.included(&mut state, hash, &orders, rejection);
                        anyhow::bail!("lost result after node execution");
                    }
                    FirstSubmission::LostBeforeExecution => anyhow::bail!("temporary internal submission error"),
                    FirstSubmission::DeterministicRefusal => {
                        return Ok(Execution::Refused("Exceeded the maximum number of events, 1000".into()))
                    }
                    FirstSubmission::Normal => {}
                }
            }
            Ok(Execution::Included(Box::new(self.included(&mut state, hash, &orders, rejection))))
        }
        fn receipt(&self, hash: Felt) -> anyhow::Result<Option<TransactionReceipt>> {
            Ok(self.state.lock().unwrap().receipts.get(&hash).cloned())
        }
        async fn head_order(&self) -> anyhow::Result<u64> {
            Ok(self.state.lock().unwrap().head)
        }
        async fn wait_for_state_change(&self) {}
    }
    fn pending(count: u64) -> (AdmissionSlots, Vec<PendingTicket>, Vec<watch::Receiver<ActionStatus>>) {
        let slots = AdmissionSlots::default();
        let mut tickets = vec![];
        let mut statuses = vec![];
        for order in 1..=count {
            let intent = Intent {
                chain: Felt::ONE,
                deployment: Felt::TWO,
                game: Felt::ONE,
                actor: Felt::from(order + 100),
                nonce: 0,
                command: Felt::ONE,
                rules: Felt::ONE,
                valid_from: 0,
                valid_until: 500,
                last_order: 100,
                arguments: if order == 2 { vec![Felt::ONE; 254] } else { vec![] },
            };
            let action = intent.identity().unwrap();
            let Slot::New(permit) = slots.reserve(intent.actor, action).unwrap() else { panic!("new actor") };
            statuses.push(permit.subscribe());
            tickets.push(PendingTicket {
                record: RecordedTicket {
                    intent,
                    envelope: Envelope {
                        action,
                        order,
                        timestamp: 10,
                        execution_config: Felt::ONE,
                        root: [order as u8; 32],
                    },
                    r: Felt::ONE,
                    s: Felt::TWO,
                },
                permit,
            });
        }
        (slots, tickets, statuses)
    }
    #[tokio::test]
    async fn included_revert_is_bisected_and_only_poison_rejected_then_next_ticket_executes() {
        let (slots, tickets, statuses) = pending(3);
        let node = Arc::new(TestNode::new(
            tickets.iter().map(|ticket| ticket.record.clone()).collect(),
            Some(2),
            FirstSubmission::Normal,
        ));
        execute(node.clone(), tickets).await.unwrap();
        let state = node.state.lock().unwrap();
        assert_eq!(state.effects, vec![1, 3]);
        assert_eq!(state.head, 3);
        assert_eq!(
            state
                .prepared
                .iter()
                .filter(|tx| tx.selector == "reject_execution")
                .map(|tx| tx.orders.clone())
                .collect::<Vec<_>>(),
            vec![vec![2]]
        );
        for (index, status) in statuses.iter().enumerate() {
            assert!(
                matches!(*status.borrow(), ActionStatus::Recorded { order, succeeded, nonce_consumed: true, .. } if order == index as u64 + 1 && succeeded == (order != 2))
            );
        }
        assert!(matches!(slots.reserve(Felt::from(102), Felt::from(999)), Ok(Slot::New(_))));
    }
    #[tokio::test]
    async fn lost_receipt_after_execution_adopts_outcome_without_duplicate_or_rejection() {
        let (_, tickets, statuses) = pending(1);
        let node = Arc::new(TestNode::new(
            tickets.iter().map(|ticket| ticket.record.clone()).collect(),
            None,
            FirstSubmission::LostAfterExecution,
        ));
        execute(node.clone(), tickets).await.unwrap();
        let state = node.state.lock().unwrap();
        assert_eq!(state.effects, vec![1]);
        assert_eq!(state.prepared.len(), 1);
        assert_eq!(state.submitted.len(), 1);
        assert!(matches!(*statuses[0].borrow(), ActionStatus::Recorded { succeeded: true, .. }));
    }
    #[tokio::test]
    async fn lost_receipt_before_execution_replays_identical_transaction_and_context() {
        let (_, tickets, statuses) = pending(1);
        let expected = batch_calldata(tickets.iter().map(|ticket| &ticket.record), false).unwrap();
        let node = Arc::new(TestNode::new(
            tickets.iter().map(|ticket| ticket.record.clone()).collect(),
            None,
            FirstSubmission::LostBeforeExecution,
        ));
        execute(node.clone(), tickets).await.unwrap();
        let state = node.state.lock().unwrap();
        assert_eq!(state.effects, vec![1]);
        assert_eq!(state.prepared.len(), 1);
        assert_eq!(state.prepared[0].payload, expected);
        assert_eq!(state.submitted, vec![Felt::ONE, Felt::ONE]);
        assert!(matches!(*statuses[0].borrow(), ActionStatus::Recorded { succeeded: true, .. }));
    }
    #[tokio::test]
    async fn deterministic_executor_refusal_rejects_one_ticket_and_advances() {
        let (_, tickets, statuses) = pending(1);
        let node = Arc::new(TestNode::new(
            tickets.iter().map(|ticket| ticket.record.clone()).collect(),
            None,
            FirstSubmission::DeterministicRefusal,
        ));
        execute(node.clone(), tickets).await.unwrap();
        assert_eq!(node.state.lock().unwrap().head, 1);
        assert!(node.state.lock().unwrap().effects.is_empty());
        assert!(matches!(*statuses[0].borrow(), ActionStatus::Recorded { succeeded: false, nonce_consumed: true, .. }));
    }
    #[test]
    fn bisection_keeps_every_ticket_and_records_only_the_poison() {
        let mut ranges = VecDeque::from_iter(std::iter::once(0..64));
        let mut successes = vec![];
        let mut rejected = vec![];
        while let Some(range) = ranges.pop_front() {
            if !range.contains(&37) {
                successes.extend(range);
            } else if range.len() == 1 {
                rejected.push(range.start);
            } else {
                split_front(&mut ranges, range);
            }
        }
        assert_eq!(rejected, vec![37]);
        assert_eq!(successes, (0..64).filter(|id| *id != 37).collect::<Vec<_>>());
        for transient in ["nonce mismatch", "queue full", "out of order", "timeout"] {
            assert!(!deterministic_limit(transient));
        }
    }
}
