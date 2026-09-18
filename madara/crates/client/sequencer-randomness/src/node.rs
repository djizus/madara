use crate::{
    protocol::Intent,
    submission::ExecutionObservers,
    ticket::{ActionStatus, RecordedTicket},
};
use anyhow::{ensure, Context};
use mc_db::MadaraBackend;
use mc_exec::MadaraBlockViewExecutionExt;
use mc_mempool::Mempool;
use mc_submit_tx::SubmitTransaction;
use mp_convert::ToFelt;
use mp_receipt::TransactionReceipt;
use mp_rpc::v0_10_2::{BroadcastedInvokeTxn, BroadcastedInvokeTxnV3};
use mp_transactions::{InvokeTransactionV3, ResourceBounds, ResourceBoundsMapping};
use starknet_core::utils::get_selector_from_name;
use starknet_signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::sync::Arc;

pub(crate) struct Node {
    pub backend: Arc<MadaraBackend>,
    pub mempool: Arc<Mempool>,
    pub submit: Arc<dyn SubmitTransaction>,
    pub observers: ExecutionObservers,
    pub deployment: Felt,
    pub key: SigningKey,
    pub l2_gas: u64,
}

pub(crate) enum Execution {
    Included(Box<TransactionReceipt>),
    Refused(String),
}

impl Node {
    /// Reconnect catch-up reads canonical chain data, never a ticket database. The
    /// bounded window covers active client retries; older nonces fail closed.
    pub async fn recorded_action(&self, intent: &Intent) -> anyhow::Result<Option<ActionStatus>> {
        let backend = self.backend.clone();
        let account = self.observers.account;
        let intent = intent.clone();
        tokio::task::spawn_blocking(move || {
            let mut block = backend.block_view_on_latest();
            for _ in 0..256 {
                let Some(view) = block else {
                    break;
                };
                for transaction in view.get_executed_transactions(..)?.into_iter().rev() {
                    let mp_transactions::Transaction::Invoke(invoke) = transaction.transaction else {
                        continue;
                    };
                    if *invoke.sender_address() != account
                        || transaction.receipt.execution_result() != mp_receipt::ExecutionResult::Succeeded
                    {
                        continue;
                    }
                    if let Some(status) = recorded_intent(invoke.calldata(), &transaction.receipt, &intent)? {
                        return Ok(Some(status));
                    }
                }
                block = view.parent_block().map(Into::into);
            }
            Ok(None)
        })
        .await?
    }

    pub async fn view(&self, contract: Felt, name: &'static str, args: Vec<Felt>) -> anyhow::Result<Vec<Felt>> {
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || {
            let view = backend.block_view_on_latest().context("chain has no execution state")?;
            Ok(view.new_execution_context()?.call_contract(&contract, &get_selector_from_name(name)?, &args)?)
        })
        .await?
    }

    pub async fn world_view(&self, name: &'static str, args: Vec<Felt>) -> anyhow::Result<Vec<Felt>> {
        self.view(self.deployment, name, args).await
    }

    pub fn nonce(&self, account: Felt) -> anyhow::Result<Felt> {
        self.backend.view_on_latest().get_contract_nonce(&account)?.context("account is not deployed")
    }

    pub fn timestamp(&self) -> anyhow::Result<u64> {
        Ok(self
            .backend
            .block_view_on_last_confirmed()
            .context("chain has no confirmed timestamp")?
            .get_block_info()?
            .header
            .block_timestamp
            .0)
    }

    pub async fn head(&self) -> anyhow::Result<(u64, u64, Felt)> {
        let fields = self.world_view("get_head", vec![]).await?;
        let [order, timestamp, state] = fields.as_slice() else { anyhow::bail!("malformed execution head") };
        Ok(((*order).try_into()?, (*timestamp).try_into()?, *state))
    }

    pub fn prepare(
        &self,
        to: Felt,
        selector: &'static str,
        payload: Vec<Felt>,
    ) -> anyhow::Result<(Felt, BroadcastedInvokeTxn)> {
        let mut calldata = vec![Felt::ONE, to, get_selector_from_name(selector)?, Felt::from(payload.len() as u64)];
        calldata.extend(payload);
        let mut transaction = InvokeTransactionV3 {
            sender_address: self.observers.account,
            nonce: self.nonce(self.observers.account)?,
            calldata: Arc::new(calldata),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds::default(),
                l2_gas: ResourceBounds { max_amount: self.l2_gas, max_price_per_unit: 0 },
                l1_data_gas: Some(ResourceBounds::default()),
            },
            ..Default::default()
        };
        let hash = transaction.compute_hash(self.backend.chain_config().chain_id.clone().to_felt(), false);
        let signature = self.key.sign(&hash)?;
        transaction.signature = Arc::new(vec![signature.r, signature.s]);
        let rpc = transaction.to_rpc_v0_10_2();
        Ok((
            hash,
            BroadcastedInvokeTxn::V3(BroadcastedInvokeTxnV3 { inner: rpc.inner, proof: None, proof_facts: None }),
        ))
    }

    /// Subscribe before submitting. Observations recover the canonical receipt after
    /// lag or reconnect; no interval polls or self-HTTP calls enter the execution path.
    pub async fn execute(&self, hash: Felt, transaction: BroadcastedInvokeTxn) -> anyhow::Result<Execution> {
        let mut status = self.mempool.watch_transaction_status(hash)?;
        let mut refusal = self.observers.watch(hash);
        if let Some(receipt) = self.receipt(hash)? {
            return Ok(Execution::Included(Box::new(receipt)));
        }
        if self.mempool.get_transaction_status(&hash)?.is_none() {
            match self.submit.submit_invoke_transaction(transaction).await {
                Ok(accepted) => {
                    ensure!(accepted.transaction_hash == hash, "validated submission returned a different hash")
                }
                Err(error) if self.mempool.get_transaction_status(&hash)?.is_none() => return Err(error.into()),
                Err(_) => {} // Submission completed even though its response was lost.
            }
        }
        loop {
            if let Some(receipt) = self.receipt(hash)? {
                return Ok(Execution::Included(Box::new(receipt)));
            }
            if let Some(reason) = refusal.receiver.borrow_and_update().clone() {
                return Ok(Execution::Refused(reason));
            }
            tokio::select! {
                update = status.recv() => { ensure!(update.is_some(), "node transaction observation stopped"); }
                update = refusal.receiver.changed() => { update.context("execution refusal observation stopped")?; }
            }
        }
    }

    pub fn receipt(&self, hash: Felt) -> anyhow::Result<Option<TransactionReceipt>> {
        self.mempool.find_transaction_by_hash(&hash)?.map(|view| Ok(view.get_transaction()?.receipt)).transpose()
    }

    /// Let Madara finish any transactions it retained across restart before assigning
    /// orders from the recovered head. The application does not reconstruct tickets.
    pub async fn drain_retained(&self) -> anyhow::Result<()> {
        self.mempool.wait_until_loaded().await?;
        let mut retained: Vec<Felt> = self
            .mempool
            .snapshot_transaction_hashes_matching(0, usize::MAX, false, |tx| {
                tx.contract_address == self.observers.account
            })
            .await
            .into_iter()
            .map(|item| item.transaction_hash)
            .collect();
        if let Some(mut block) = self.backend.block_view_on_preconfirmed() {
            block.refresh_with_candidates();
            retained.extend(
                block
                    .candidate_transactions()
                    .iter()
                    .filter(|tx| tx.contract_address == self.observers.account)
                    .map(|tx| tx.hash),
            );
        }
        retained.sort_unstable();
        retained.dedup();
        for item in retained {
            let mut status = self.mempool.watch_transaction_status(item)?;
            // The chain watcher may not have published a restored candidate yet.
            while self.receipt(item)?.is_none() && (status.current().is_some() || self.is_candidate(item)) {
                ensure!(status.recv().await.is_some(), "retained transaction observer stopped");
            }
        }
        Ok(())
    }

    fn is_candidate(&self, hash: Felt) -> bool {
        self.backend.block_view_on_preconfirmed().is_some_and(|mut block| {
            block.refresh_with_candidates();
            block.candidate_transactions().iter().any(|transaction| transaction.hash == hash)
        })
    }
}

fn recorded_intent(
    calldata: &[Felt],
    receipt: &TransactionReceipt,
    intent: &Intent,
) -> anyhow::Result<Option<ActionStatus>> {
    let [count, target, selector, length, payload @ ..] = calldata else { return Ok(None) };
    if *count != Felt::ONE || *target != intent.deployment || usize::try_from(*length)? != payload.len() {
        return Ok(None);
    }
    let mut fields = payload;
    let count = if *selector == get_selector_from_name("execute_batch")? {
        let Some((count, rest)) = fields.split_first() else { anyhow::bail!("truncated recorded batch") };
        fields = rest;
        usize::try_from(*count)?
    } else if *selector == get_selector_from_name("execute")?
        || *selector == get_selector_from_name("reject_execution")?
    {
        1
    } else {
        return Ok(None);
    };
    ensure!(count > 0 && count <= 64, "invalid recorded batch size");
    let tickets = (0..count).map(|_| RecordedTicket::take_calldata(&mut fields)).collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(fields.is_empty(), "trailing recorded transaction data");
    if !tickets.iter().any(|ticket| ticket.intent == *intent) {
        return Ok(None);
    }
    let outcomes = crate::execution::receipt_outcomes(tickets.iter(), *receipt.transaction_hash(), receipt)?;
    Ok(outcomes.into_iter().zip(tickets).find_map(|(outcome, ticket)| (ticket.intent == *intent).then_some(outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Envelope;
    use mp_receipt::{Event, InvokeTransactionReceipt};

    #[test]
    fn restart_reconciliation_attributes_the_matching_intent_inside_a_batch() {
        let intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::TWO,
            game: Felt::from(9),
            actor: Felt::from(55),
            nonce: 3,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 0,
            valid_until: 500,
            last_order: 100,
            arguments: vec![Felt::from(7)],
        };
        let first = RecordedTicket {
            envelope: Envelope {
                action: intent.identity().unwrap(),
                order: 7,
                timestamp: 10,
                execution_config: Felt::ONE,
                root: [123; 32],
            },
            intent: intent.clone(),
            r: Felt::ONE,
            s: Felt::TWO,
        };
        let mut second = first.clone();
        second.intent.actor = Felt::from(56);
        second.envelope.action = second.intent.identity().unwrap();
        second.envelope.order = 8;
        let mut payload = vec![Felt::TWO];
        payload.extend(first.calldata().unwrap());
        payload.extend(second.calldata().unwrap());
        let mut calldata = vec![
            Felt::ONE,
            intent.deployment,
            get_selector_from_name("execute_batch").unwrap(),
            Felt::from(payload.len() as u64),
        ];
        calldata.extend(payload);
        let receipt = TransactionReceipt::Invoke(InvokeTransactionReceipt {
            transaction_hash: Felt::from(99),
            events: [&first, &second]
                .iter()
                .map(|ticket| Event {
                    from_address: intent.deployment,
                    keys: vec![
                        get_selector_from_name("RecordingEvent").unwrap(),
                        get_selector_from_name("ExecutionRecorded").unwrap(),
                    ],
                    data: vec![
                        ticket.intent.game,
                        ticket.intent.actor,
                        ticket.intent.nonce.into(),
                        Felt::ONE,
                        ticket.envelope.order.into(),
                        Felt::ONE,
                        Felt::ZERO,
                    ],
                })
                .collect(),
            ..Default::default()
        });
        assert!(
            matches!(recorded_intent(&calldata, &receipt, &intent).unwrap(), Some(ActionStatus::Recorded { order: 7, transaction_hash, succeeded: true, .. }) if transaction_hash == Felt::from(99))
        );
        assert!(matches!(
            recorded_intent(&calldata, &receipt, &second.intent).unwrap(),
            Some(ActionStatus::Recorded { order: 8, .. })
        ));
        let mut different = intent.clone();
        different.arguments[0] += Felt::ONE;
        assert!(recorded_intent(&calldata, &receipt, &different).unwrap().is_none());
        calldata.pop();
        assert!(recorded_intent(&calldata, &receipt, &intent).unwrap().is_none());
    }
}
