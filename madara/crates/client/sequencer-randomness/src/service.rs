use crate::{
    journal::{Authorization, ChainProgress, Journal, Record},
    protocol::Intent,
    settlement::SettlementChecks,
    submission::execution_calldata,
    ticket::{timestamp_in_bounds, Context as TicketContext, State as TicketState},
};
use anyhow::{bail, Context};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use starknet_accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount};
use starknet_core::{
    types::{
        BlockId, BlockTag, BroadcastedInvokeTransaction, Call, ExecutionResult, Felt, FunctionCall,
        MaybePreConfirmedBlockWithTxHashes, StarknetError, TransactionStatus,
    },
    utils::get_selector_from_name,
};
use starknet_providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError};
use starknet_signers::{LocalWallet, SigningKey};
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};

type Sequencer = SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>;
const EXECUTION_LAG_ALERT_SECONDS: u64 = 300;
const L2_GAS: u64 = 1_200_000_000;
const HEAD: BlockId = BlockId::Tag(BlockTag::PreConfirmed);

pub struct Configuration {
    pub account: Felt,
    pub deployment: Felt,
    pub epoch: u64,
    pub primary: String,
    pub standby: String,
}

impl Configuration {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            account: Felt::from_hex(&required("RANDOMNESS_ACCOUNT")?)?,
            deployment: Felt::from_hex(&required("RANDOMNESS_DEPLOYMENT")?)?,
            epoch: required("RANDOMNESS_EPOCH")?.parse()?,
            primary: required("RANDOMNESS_JOURNAL_PRIMARY")?,
            standby: required("RANDOMNESS_JOURNAL_STANDBY")?,
        })
    }
}

pub(crate) fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("missing {name}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    intent: Vec<Felt>,
    r: Felt,
    s: Felt,
}

#[derive(Serialize)]
struct Accepted {
    action: Felt,
    order: u64,
}

struct AdmissionRequest {
    action: ActionRequest,
    response: oneshot::Sender<Result<Accepted, StatusCode>>,
    received: Instant,
}

struct Service {
    config: Configuration,
    account: Sequencer,
    journal: Journal,
    settlement: SettlementChecks,
}

pub fn validate_native_schema(path: &std::path::Path) -> anyhow::Result<()> {
    SettlementChecks::load(&std::fs::read_to_string(path)?, None)?;
    Ok(())
}

/// Both placements use this worker. Disconnecting HTTP clients cannot cancel accepted work.
pub async fn run() -> anyhow::Result<()> {
    let config = Configuration::from_env()?;
    let provider = JsonRpcClient::new(HttpTransport::new(required("RANDOMNESS_RPC_URL")?.parse::<url::Url>()?));
    let chain = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(chain) = provider.chain_id().await {
                break chain;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("chain RPC did not become ready")?;
    let signer =
        LocalWallet::from(SigningKey::from_secret_scalar(Felt::from_hex(&required("RANDOMNESS_PRIVATE_KEY")?)?));
    let account = SingleOwnerAccount::new(provider, signer, config.account, chain, ExecutionEncoding::New);
    let journal = Journal::connect(&config.primary, &config.standby, config.epoch).await?;
    let schema = std::fs::read_to_string(required("RANDOMNESS_NATIVE_SCHEMA")?)?;
    let l2 = std::env::var("RANDOMNESS_L2_RPC_URL").ok().filter(|url| !url.is_empty());
    let settlement = SettlementChecks::load(&schema, l2.as_deref())?;
    let mut service = Service { config, account, journal, settlement };
    service.recover().await?;
    let address: SocketAddr = required("RANDOMNESS_HTTP_BIND")?.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let (sender, receiver) = mpsc::channel(64);
    let router = Router::new().route("/actions", post(admit)).with_state(sender);
    tokio::select! {
        result = axum::serve(listener, router) => result.context("admission server"),
        result = service.work(receiver) => result,
    }
}

async fn admit(
    State(sender): State<mpsc::Sender<AdmissionRequest>>,
    Json(action): Json<ActionRequest>,
) -> Result<Json<Accepted>, StatusCode> {
    let (response, receiver) = oneshot::channel();
    sender
        .try_send(AdmissionRequest { action, response, received: Instant::now() })
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    receiver.await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.map(Json)
}

impl Service {
    async fn work(&mut self, mut receiver: mpsc::Receiver<AdmissionRequest>) -> anyhow::Result<()> {
        while let Some(request) = receiver.recv().await {
            let queue_ms = request.received.elapsed().as_secs_f64() * 1000.0;
            // Invalid intent never enters the journal. Storage or execution ambiguity stops the worker.
            let intent = match Intent::decode(&request.action.intent) {
                Ok(intent) => intent,
                Err(_) => {
                    let _ = request.response.send(Err(StatusCode::BAD_REQUEST));
                    continue;
                }
            };
            let record = match self.accept(intent, request.action.r, request.action.s).await? {
                Ok(record) => record,
                Err(status) => {
                    let _ = request.response.send(Err(status));
                    continue;
                }
            };
            tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
                order = record.envelope.order, queue_ms, admission_ms = request.received.elapsed().as_secs_f64() * 1000.0,
                "randomness_admission");
            let _ =
                request.response.send(Ok(Accepted { action: record.envelope.action, order: record.envelope.order }));
            self.execute(record).await?;
        }
        bail!("admission channel closed")
    }

    async fn view(&self, name: &str, calldata: Vec<Felt>) -> anyhow::Result<Vec<Felt>> {
        Ok(self
            .account
            .provider()
            .call(
                FunctionCall {
                    contract_address: self.config.deployment,
                    entry_point_selector: get_selector_from_name(name)?,
                    calldata,
                },
                HEAD,
            )
            .await?)
    }

    async fn admission_view(&self, name: &str, calldata: Vec<Felt>) -> anyhow::Result<Option<Vec<Felt>>> {
        match self.view(name, calldata).await {
            Ok(fields) => Ok(Some(fields)),
            Err(error)
                if matches!(
                    error.downcast_ref::<ProviderError>(),
                    Some(ProviderError::StarknetError(StarknetError::ContractError(_)))
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn accept(&mut self, intent: Intent, r: Felt, s: Felt) -> anyhow::Result<Result<Record, StatusCode>> {
        let started = Instant::now();
        if let Some(record) = self.journal.find_record(intent.identity()?).await? {
            return Ok(Ok(record));
        }
        if intent.chain != self.account.chain_id() || intent.deployment != self.config.deployment {
            return Ok(Err(StatusCode::BAD_REQUEST));
        }
        let Some(fields) = self.admission_view("get_admission", vec![intent.game, intent.actor]).await? else {
            return Ok(Err(StatusCode::BAD_REQUEST));
        };
        let [key, rules, config, nonce, order, predecessor, state, observed_time] = fields.as_slice() else {
            bail!("malformed native admission context");
        };
        if !admission_state_matches(&intent, *rules, *nonce) {
            return Ok(Err(StatusCode::BAD_REQUEST));
        }
        // Pending RPC calls and headers can synthesize wall time ahead of the batcher.
        // Bind to the last closed timestamp before sampling; expiry still uses the current admission view.
        let timestamp = match self.account.provider().get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest)).await? {
            MaybePreConfirmedBlockWithTxHashes::Block(block) => block.timestamp,
            MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(_) => bail!("expected a confirmed timestamp"),
        };
        if !admission_time_is_valid(&intent, timestamp, (*observed_time).try_into()?) {
            return Ok(Err(StatusCode::BAD_REQUEST));
        }
        let context = TicketContext {
            order: (*order).try_into()?,
            predecessor: *predecessor,
            preceding_state: *state,
            timestamp,
            execution_config: *config,
            l2_gas: L2_GAS,
        };
        if context.validate(&intent).is_err()
            || !matches!(starknet_crypto::verify(key, &intent.identity()?, &r, &s), Ok(true))
        {
            return Ok(Err(StatusCode::BAD_REQUEST));
        }
        if self.settlement.is_settlement(&intent) {
            if let Some(status) = self.settlement_refusal(&intent, timestamp, &fields).await? {
                return Ok(Err(status));
            }
        }
        let checks_ms = started.elapsed().as_secs_f64() * 1000.0;
        let record = self.journal.accept(intent, context, Authorization { public_key: *key, r, s }).await?;
        tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
            order = record.envelope.order, checks_ms, "randomness_admission_checks");
        Ok(Ok(record))
    }

    async fn settlement_refusal(
        &self,
        intent: &Intent,
        timestamp: u64,
        admission: &[Felt],
    ) -> anyhow::Result<Option<StatusCode>> {
        let Some(policy) = self.admission_view("settlement_admission", vec![intent.game, intent.actor]).await? else {
            return Ok(Some(StatusCode::BAD_REQUEST));
        };
        match self.settlement.verify(intent, &policy).await {
            Ok(true) => {}
            Ok(false) => return Ok(Some(StatusCode::BAD_REQUEST)),
            Err(error) => {
                tracing::warn!(target: "sequencer_randomness", action = %intent.identity()?.to_hex_string(),
                    error = %error, "cosmetic admission unavailable before ticket acceptance");
                return Ok(Some(StatusCode::SERVICE_UNAVAILABLE));
            }
        }
        let Some(current) = self.admission_view("get_admission", vec![intent.game, intent.actor]).await? else {
            return Ok(Some(StatusCode::BAD_REQUEST));
        };
        if !admission_survived_external_checks(intent, timestamp, admission, &current)? {
            return Ok(Some(StatusCode::BAD_REQUEST));
        }
        Ok(None)
    }

    async fn result(&self, order: u64) -> anyhow::Result<Option<(ChainProgress, bool)>> {
        let fields = self.view("get_result", vec![order.into()]).await?;
        let [status, binding, result, state] = fields.as_slice() else {
            bail!("malformed native execution result");
        };
        if *status == Felt::ZERO {
            if [binding, result, state].iter().any(|value| **value != Felt::ZERO) {
                bail!("unexecuted order contains a result");
            }
            return Ok(None);
        }
        if *status != Felt::ONE && *status != Felt::TWO {
            bail!("unknown execution status");
        }
        Ok(Some((ChainProgress { order, binding: *binding, state: *state, result: *result }, *status == Felt::TWO)))
    }

    async fn recover(&mut self) -> anyhow::Result<()> {
        let prefix = self.journal.accepted_prefix().await?;
        let mut chain = Vec::new();
        for record in &prefix {
            match self.result(record.envelope.order).await? {
                Some((progress, _)) => chain.push(progress),
                None => break,
            }
        }
        if self.result(prefix.len() as u64 + 1).await?.is_some() {
            bail!("chain extends beyond retained journal");
        }
        let records = self.journal.recover(&chain).await?;
        for record in records {
            self.execute(record).await?;
        }
        Ok(())
    }

    async fn execute(&self, record: Record) -> anyhow::Result<()> {
        if record.state == TicketState::Consumed {
            return Ok(());
        }
        if let Some((progress, rejected)) = self.result(record.envelope.order).await? {
            return self.complete(&record, progress, rejected).await;
        }
        report_execution_lag(&record, SystemTime::now());
        let transaction = self.submit(&record).await?;
        tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                if let Some((progress, rejected)) = self.result(record.envelope.order).await? {
                    return self.complete(&record, progress, rejected).await;
                }
                require_unreverted(&self.account.provider().get_transaction_status(transaction).await?)?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("pending ticket stopped without a fresh draw")?
    }

    async fn submit(&self, record: &Record) -> anyhow::Result<Felt> {
        let retained = self.journal.submissions(record.envelope.action).await?;
        for submission in retained.iter().filter(|submission| submission.action == record.envelope.action) {
            match self.account.provider().get_transaction_status(submission.transaction_hash).await {
                Ok(status) => {
                    require_unreverted(&status)?;
                    return Ok(submission.transaction_hash);
                }
                Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if let Some(submission) = retained
            .iter()
            .rev()
            .find(|submission| submission.action == record.envelope.action && submission.epoch == self.config.epoch)
        {
            let transaction: BroadcastedInvokeTransaction = serde_json::from_slice(&submission.bytes)?;
            let (expected_hash, expected) =
                self.prepare_transaction(record, transaction.broadcasted_invoke_txn_v3.nonce).await?;
            if expected_hash != submission.transaction_hash
                || serde_json::to_vec(&transaction)? != serde_json::to_vec(&expected)?
            {
                bail!("retained transaction differs from its accepted binding");
            }
            let received = self.account.provider().add_invoke_transaction(transaction).await?;
            if received.transaction_hash != expected_hash {
                bail!("resubmission hash mismatch");
            }
            return Ok(expected_hash);
        }
        self.prepare_submission(record).await
    }

    async fn prepare_submission(&self, record: &Record) -> anyhow::Result<Felt> {
        let started = Instant::now();
        let nonce = self.account.get_nonce().await?;
        let (hash, transaction) = self.prepare_transaction(record, nonce).await?;
        self.journal.record_submission(record.envelope.action, hash, &serde_json::to_vec(&transaction)?).await?;
        let received = self.account.provider().add_invoke_transaction(transaction).await?;
        if received.transaction_hash != hash {
            bail!("submission hash mismatch");
        }
        tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
            order = record.envelope.order, transaction = %hash.to_hex_string(),
            submission_ms = started.elapsed().as_secs_f64() * 1000.0, "randomness_submission");
        Ok(hash)
    }

    async fn prepare_transaction(
        &self,
        record: &Record,
        nonce: Felt,
    ) -> anyhow::Result<(Felt, BroadcastedInvokeTransaction)> {
        let calls = vec![Call {
            to: self.config.deployment,
            selector: get_selector_from_name("execute")?,
            calldata: execution_calldata(&record.intent, &record.envelope, record.authorization, self.config.epoch)?,
        }];
        let prepared = self
            .account
            .execute_v3(calls)
            .nonce(nonce)
            .l1_gas(0)
            .l1_gas_price(0)
            .l2_gas(record.envelope.l2_gas)
            .l2_gas_price(0)
            .l1_data_gas(0)
            .l1_data_gas_price(0)
            .tip(0)
            .prepared()?;
        let hash = prepared.transaction_hash(false);
        let transaction = prepared.get_invoke_request(false, false).await?;
        Ok((hash, transaction))
    }

    async fn complete(&self, record: &Record, progress: ChainProgress, rejected: bool) -> anyhow::Result<()> {
        let started = Instant::now();
        if progress.binding != record.envelope.binding()? {
            bail!("chain binding mismatch");
        }
        self.journal.finish(record.envelope.action, progress.result, progress.state, rejected).await?;
        self.journal.consume(record.envelope.action).await?;
        tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
            order = record.envelope.order, persistence_ms = started.elapsed().as_secs_f64() * 1000.0,
            "randomness_result_persistence");
        Ok(())
    }
}

fn admission_state_matches(intent: &Intent, rules: Felt, nonce: Felt) -> bool {
    rules == intent.rules && nonce == Felt::from(intent.nonce) && intent.nonce < u64::MAX
}

fn admission_time_is_valid(intent: &Intent, recorded: u64, observed: u64) -> bool {
    timestamp_in_bounds(recorded, observed) && recorded >= intent.valid_from && observed <= intent.valid_until
}

// External token reads may outlast the proposal's window or overlap a registry change.
fn admission_survived_external_checks(
    intent: &Intent,
    recorded: u64,
    before: &[Felt],
    after: &[Felt],
) -> anyhow::Result<bool> {
    if before.len() != 8 || after.len() != 8 {
        bail!("malformed native admission context");
    }
    Ok(before[..7] == after[..7] && admission_time_is_valid(intent, recorded, after[7].try_into()?))
}

// Host time is telemetry only. Neither a long outage nor a broken host clock cancels accepted work.
fn report_execution_lag(record: &Record, now: SystemTime) {
    let Ok(elapsed) = now.duration_since(UNIX_EPOCH) else {
        tracing::warn!(target: "sequencer_randomness", order = record.envelope.order,
            "execution lag unavailable: host clock precedes Unix epoch");
        return;
    };
    let execution_lag_seconds = elapsed.as_secs().saturating_sub(record.envelope.timestamp);
    tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
        order = record.envelope.order, execution_lag_seconds, "randomness_execution_lag");
    if execution_lag_seconds > EXECUTION_LAG_ALERT_SECONDS {
        tracing::warn!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
            order = record.envelope.order, execution_lag_seconds, threshold_seconds = EXECUTION_LAG_ALERT_SECONDS,
            "accepted ticket execution delayed; retaining recorded context");
    }
}

fn require_unreverted(status: &TransactionStatus) -> anyhow::Result<()> {
    if matches!(
        status,
        TransactionStatus::PreConfirmed(ExecutionResult::Reverted { .. })
            | TransactionStatus::AcceptedOnL2(ExecutionResult::Reverted { .. })
            | TransactionStatus::AcceptedOnL1(ExecutionResult::Reverted { .. })
    ) {
        bail!("recorded submission reverted; stream stopped with its binding retained");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_intent_cannot_use_an_older_closed_block_to_enter() {
        let intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::ONE,
            game: Felt::ONE,
            actor: Felt::ONE,
            nonce: 0,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 1000,
            valid_until: 1010,
            last_order: 10,
            arguments: vec![],
        };
        assert!(admission_time_is_valid(&intent, 1005, 1010));
        assert!(!admission_time_is_valid(&intent, 1005, 1011));
        assert!(!admission_time_is_valid(&intent, 999, 1005));
        assert!(!admission_time_is_valid(&intent, 1006, 1005));
        assert!(timestamp_in_bounds(1005, 1005 + 86400));
        let before = [Felt::ONE, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO, Felt::ONE, 1005u64.into()];
        let mut after = before;
        after[7] = 1010u64.into();
        assert!(admission_survived_external_checks(&intent, 1005, &before, &after).unwrap());
        after[7] = 1011u64.into();
        assert!(!admission_survived_external_checks(&intent, 1005, &before, &after).unwrap());
        for index in 0..7 {
            let mut changed = before;
            changed[index] += Felt::ONE;
            assert!(!admission_survived_external_checks(&intent, 1005, &before, &changed).unwrap());
        }
        assert!(admission_survived_external_checks(&intent, 1005, &before, &before[..7]).is_err());
    }

    #[test]
    fn admission_requires_the_current_nonce_with_a_representable_successor() {
        let mut intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::ONE,
            game: Felt::ONE,
            actor: Felt::ONE,
            nonce: 7,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 1000,
            valid_until: 1010,
            last_order: 10,
            arguments: vec![],
        };
        assert!(admission_state_matches(&intent, Felt::ONE, Felt::from(7)));
        assert!(!admission_state_matches(&intent, Felt::ONE, Felt::from(8)));
        assert!(!admission_state_matches(&intent, Felt::ONE, Felt::from(6)));
        assert!(!admission_state_matches(&intent, Felt::TWO, Felt::from(7)));
        intent.nonce = u64::MAX;
        assert!(!admission_state_matches(&intent, Felt::ONE, Felt::from(u64::MAX)));
    }

    #[test]
    fn reverted_transport_stops_at_every_finality_without_resubmitting() {
        for status in [
            TransactionStatus::PreConfirmed(ExecutionResult::Reverted { reason: "context".into() }),
            TransactionStatus::AcceptedOnL2(ExecutionResult::Reverted { reason: "bounds".into() }),
            TransactionStatus::AcceptedOnL1(ExecutionResult::Reverted { reason: "callback".into() }),
        ] {
            assert!(require_unreverted(&status).is_err());
        }
        for status in [
            TransactionStatus::Received,
            TransactionStatus::Candidate,
            TransactionStatus::PreConfirmed(ExecutionResult::Succeeded),
            TransactionStatus::AcceptedOnL2(ExecutionResult::Succeeded),
            TransactionStatus::AcceptedOnL1(ExecutionResult::Succeeded),
        ] {
            assert!(require_unreverted(&status).is_ok());
        }
    }

    #[test]
    fn admission_rejects_player_roots_context_and_transport_identity() {
        let request = serde_json::json!({"intent": [], "r": "0x1", "s": "0x2"});
        assert!(serde_json::from_value::<ActionRequest>(request.clone()).is_ok());
        for field in ["root", "context", "request_id", "transaction_hash", "authority_epoch"] {
            let mut altered = request.clone();
            altered[field] = serde_json::json!("0x1");
            assert!(serde_json::from_value::<ActionRequest>(altered).is_err());
        }
    }
}
