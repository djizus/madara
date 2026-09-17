use crate::admission::{AdmissionSlots, IpLimits, Permit, Slot};
use crate::{
    execution::{deterministic_refusal, included_failure, Attempt, ExecutionIo, Observation},
    journal::{Authorization, ChainProgress, Journal, Record},
    protocol::Intent,
    settlement::SettlementChecks,
    submission::{execution_calldata, SubmissionKind},
    ticket::{timestamp_in_bounds, Context as TicketContext, State as TicketState},
};
use anyhow::{bail, Context};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use starknet_accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount};
use starknet_core::{
    types::{
        BlockId, BlockTag, BroadcastedInvokeTransaction, Call, Felt, FunctionCall, MaybePreConfirmedBlockWithTxHashes,
        StarknetError,
    },
    utils::get_selector_from_name,
};
use starknet_providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError};
use starknet_signers::{LocalWallet, SigningKey};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};

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
    public_key: Felt,
}

#[derive(Clone, Serialize)]
pub(crate) struct Accepted {
    pub action: Felt,
    pub order: u64,
}

/// Public recovery status contains no entropy or authorization witness.
#[derive(Serialize)]
struct ActionStatus {
    action: Felt,
    order: u64,
    transaction_hash: Option<Felt>,
}

struct HttpState {
    admissions: mpsc::Sender<Work>,
    journal: Journal,
    provider: JsonRpcClient<HttpTransport>,
    slots: AdmissionSlots,
    progress: watch::Sender<u64>,
    chain: Felt,
    deployment: Felt,
}

enum Work {
    Action(Box<AdmissionRequest>),
    Rotate { transaction: Box<BroadcastedInvokeTransaction>, response: oneshot::Sender<Result<Felt, StatusCode>> },
}

struct AdmissionRequest {
    action: ActionRequest,
    permit: Permit,
    intent: Intent,
    received: Instant,
}

struct Service {
    config: Configuration,
    account: Sequencer,
    journal: Journal,
    settlement: SettlementChecks,
    progress: watch::Sender<u64>,
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
    let (progress, _) = watch::channel(0);
    let mut service = Service { config, account, journal, settlement, progress };
    loop {
        match service.recover().await {
            Ok(()) => break,
            Err(error) if error.downcast_ref::<ProviderError>().is_some() => {
                tracing::warn!(target: "sequencer_randomness", %error, "recovery transport unavailable; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }
    let address: SocketAddr = required("RANDOMNESS_HTTP_BIND")?.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let (sender, receiver) = mpsc::channel(128);
    let state = Arc::new(HttpState {
        admissions: sender,
        slots: AdmissionSlots::default(),
        progress: service.progress.clone(),
        chain,
        deployment: service.config.deployment,
        journal: Journal::connect(&service.config.primary, &service.config.standby, service.config.epoch).await?,
        provider: JsonRpcClient::new(HttpTransport::new(required("RANDOMNESS_RPC_URL")?.parse::<url::Url>()?)),
    });
    let router = Router::new()
        .route("/actions", post(admit))
        .route("/key-rotations", post(rotate))
        .route("/actions/:action", get(action_status))
        .with_state(state)
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(Arc::new(Mutex::new(IpLimits::default())), limit_requests))
        .layer(middleware::from_fn(browser_access));
    tokio::select! {
        result = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()) => result.context("admission server"),
        result = service.work(receiver) => result,
    }
}

// Public signed intents use no ambient cookies or credentials. Entropy and witnesses are never HTTP responses.
async fn browser_access(request: Request, next: Next) -> Response {
    let mut response = if request.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().expect("static header"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS".parse().expect("static header"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type".parse().expect("static header"));
    response
}

async fn limit_requests(
    State(limits): State<Arc<Mutex<IpLimits>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != Method::OPTIONS
        && !limits.lock().expect("IP limits poisoned").allow(peer.ip(), Instant::now())
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    next.run(request).await
}

fn verify_request(action: &ActionRequest, chain: Felt, deployment: Felt) -> Result<Intent, StatusCode> {
    let intent = Intent::decode(&action.intent).map_err(|_| StatusCode::BAD_REQUEST)?;
    let digest = intent.identity().map_err(|_| StatusCode::BAD_REQUEST)?;
    if intent.chain != chain
        || intent.deployment != deployment
        || !matches!(starknet_crypto::verify(&action.public_key, &digest, &action.r, &action.s), Ok(true))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(intent)
}

async fn verify_registered_actor(
    provider: &JsonRpcClient<HttpTransport>,
    intent: &Intent,
    public_key: Felt,
) -> Result<(), StatusCode> {
    let fields = provider
        .call(
            FunctionCall {
                contract_address: intent.deployment,
                entry_point_selector: get_selector_from_name("get_admission").expect("static selector"),
                calldata: vec![intent.game, intent.actor],
            },
            HEAD,
        )
        .await
        .map_err(|error| match error {
            ProviderError::StarknetError(StarknetError::ContractError(_)) => StatusCode::BAD_REQUEST,
            error => status_unavailable(error),
        })?;
    match fields.as_slice() {
        [key, _, _, _, _, _, _] if *key == public_key => Ok(()),
        [_, _, _, _, _, _, _] => Err(StatusCode::BAD_REQUEST),
        _ => Err(status_unavailable("malformed native admission context")),
    }
}

async fn admit(
    State(state): State<Arc<HttpState>>,
    Json(action): Json<ActionRequest>,
) -> Result<Json<Accepted>, StatusCode> {
    // Reject invalid signatures before RPC, then bind the key to the actor before
    // reserving a slot. Execution rechecks the registration after queueing.
    let intent = verify_request(&action, state.chain, state.deployment)?;
    verify_registered_actor(&state.provider, &intent, action.public_key).await?;
    let digest = intent.identity().map_err(|_| StatusCode::BAD_REQUEST)?;
    let receiver = match state.slots.reserve(intent.actor, digest)? {
        Slot::Existing(receiver) => receiver,
        Slot::New(permit) => {
            let receiver = permit.subscribe();
            state
                .admissions
                .try_send(Work::Action(Box::new(AdmissionRequest { action, permit, intent, received: Instant::now() })))
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            receiver
        }
    };
    crate::admission::decision(receiver).await.map(Json)
}

async fn rotate(
    State(state): State<Arc<HttpState>>,
    Json(transaction): Json<BroadcastedInvokeTransaction>,
) -> Result<Json<Felt>, StatusCode> {
    let (response, receiver) = oneshot::channel();
    state
        .admissions
        .try_send(Work::Rotate { transaction: Box::new(transaction), response })
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    receiver.await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.map(Json)
}

async fn action_status(
    State(state): State<Arc<HttpState>>,
    Path(action): Path<String>,
) -> Result<Json<ActionStatus>, StatusCode> {
    let action = Felt::from_hex(&action).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut progress = state.progress.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let status = retained_status(&state, action).await?;
        if status.transaction_hash.is_some() {
            return Ok(Json(status));
        }
        match tokio::time::timeout_at(deadline, progress.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(StatusCode::SERVICE_UNAVAILABLE),
            Err(_) => return Ok(Json(status)),
        }
    }
}

async fn retained_status(state: &HttpState, action: Felt) -> Result<ActionStatus, StatusCode> {
    let record = state.journal.find_record(action).await.map_err(status_unavailable)?.ok_or(StatusCode::NOT_FOUND)?;
    let submissions = state.journal.submissions(action).await.map_err(status_unavailable)?;
    // Only the receipt carrying the recorded outcome completes the action. An earlier
    // reverted execution may precede the transaction recording its terminal rejection.
    let mut transaction_hash = None;
    for submission in submissions {
        match state.provider.get_transaction_receipt(submission.transaction_hash).await {
            Ok(receipt) => {
                if crate::execution::receipt_outcome(&record, &receipt.receipt).map_err(status_unavailable)?.is_some() {
                    transaction_hash = Some(submission.transaction_hash);
                    break;
                }
            }
            Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => {}
            Err(error) => return Err(status_unavailable(error)),
        }
    }
    Ok(ActionStatus { action, order: record.envelope.order, transaction_hash })
}

fn status_unavailable(error: impl std::fmt::Display) -> StatusCode {
    tracing::warn!(target: "sequencer_randomness", %error, "action_status_unavailable");
    StatusCode::SERVICE_UNAVAILABLE
}

impl Service {
    async fn work(&mut self, mut receiver: mpsc::Receiver<Work>) -> anyhow::Result<()> {
        while let Some(work) = receiver.recv().await {
            let request = match work {
                Work::Action(request) => *request,
                Work::Rotate { transaction, response } => {
                    let result = self.rotate(*transaction).await?;
                    let _ = response.send(result);
                    continue;
                }
            };
            let queue_ms = request.received.elapsed().as_secs_f64() * 1000.0;
            let record = match self.accept(request.intent, request.action.r, request.action.s).await {
                Ok(Ok(record)) => record,
                Ok(Err(status)) => {
                    request.permit.resolve(Err(status));
                    continue;
                }
                Err(error) if error.downcast_ref::<ProviderError>().is_some() => {
                    tracing::warn!(target: "sequencer_randomness", %error, "admission RPC unavailable before acceptance");
                    request.permit.resolve(Err(StatusCode::SERVICE_UNAVAILABLE));
                    continue;
                }
                Err(error) => return Err(error),
            };
            tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
                order = record.envelope.order, queue_ms, admission_ms = request.received.elapsed().as_secs_f64() * 1000.0,
                "randomness_admission");
            request.permit.resolve(Ok(Accepted { action: record.envelope.action, order: record.envelope.order }));
            self.execute(record).await?;
            self.progress.send_modify(|version| *version = version.wrapping_add(1));
        }
        bail!("admission channel closed")
    }

    async fn rotate(&self, transaction: BroadcastedInvokeTransaction) -> anyhow::Result<Result<Felt, StatusCode>> {
        let hash = match crate::rotation::validate(
            self.account.provider(),
            self.config.deployment,
            self.account.chain_id(),
            &transaction,
        )
        .await
        {
            Ok(hash) => hash,
            Err(error) => {
                tracing::warn!(target: "sequencer_randomness", %error, "key rotation refused");
                return Ok(Err(StatusCode::BAD_REQUEST));
            }
        };
        self.journal.begin_key_rotation(hash, &serde_json::to_vec(&transaction)?).await?;
        let (_, success) = crate::rotation::resume(self.account.provider(), &self.journal, self.account.chain_id())
            .await?
            .context("rotation disappeared before execution")?;
        Ok(if success { Ok(hash) } else { Err(StatusCode::UNPROCESSABLE_ENTITY) })
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
        let [key, rules, config, nonce, order, state, observed_time] = fields.as_slice() else {
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

    async fn head(&self) -> anyhow::Result<(u64, u64, Felt)> {
        let fields = self.view("get_head", vec![]).await?;
        let [order, timestamp, state] = fields.as_slice() else {
            bail!("malformed recorded head");
        };
        Ok(((*order).try_into()?, (*timestamp).try_into()?, *state))
    }

    async fn result(&self, record: &Record) -> anyhow::Result<Option<(ChainProgress, bool)>> {
        for submission in self.journal.submissions(record.envelope.action).await? {
            let transaction: BroadcastedInvokeTransaction = serde_json::from_slice(&submission.bytes)?;
            let execution = crate::submission::decode_execution(
                &transaction.broadcasted_invoke_txn_v3.calldata,
                self.config.deployment,
            )?;
            if execution.intent != record.intent || execution.envelope != record.envelope {
                bail!("retained transaction does not match accepted binding");
            }
            let receipt = match self.account.provider().get_transaction_receipt(submission.transaction_hash).await {
                Ok(receipt) => receipt,
                Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => continue,
                Err(error) => return Err(error.into()),
            };
            if *receipt.receipt.transaction_hash() != submission.transaction_hash {
                bail!("receipt transaction hash mismatch");
            }
            if let Some(outcome) = crate::execution::receipt_outcome(record, &receipt.receipt)? {
                return Ok(Some(outcome));
            }
        }
        Ok(None)
    }

    async fn recover(&mut self) -> anyhow::Result<()> {
        let prefix = self.journal.accepted_prefix().await?;
        let chain = loop {
            let head = self.head().await?;
            if head.0 > prefix.len() as u64 {
                bail!("chain extends beyond retained journal");
            }
            let mut chain = Vec::new();
            for record in prefix.iter().take(head.0 as usize) {
                match self.result(record).await? {
                    Some((progress, _)) => chain.push(progress),
                    None => break,
                }
            }
            // An observed head without its receipt is incomplete evidence, never a rejection.
            if chain.len() == head.0 as usize && self.head().await? == head {
                let expected = chain.last().map_or(Felt::ZERO, |progress| progress.state);
                if expected != head.2 {
                    bail!("receipt prefix does not match recorded head");
                }
                break chain;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let records = self.journal.recover(&chain).await?;
        for record in records {
            self.execute(record).await?;
        }
        crate::rotation::resume(self.account.provider(), &self.journal, self.account.chain_id()).await?;
        Ok(())
    }

    async fn execute(&self, record: Record) -> anyhow::Result<()> {
        if record.state == TicketState::Consumed {
            return Ok(());
        }
        report_execution_lag(&record, SystemTime::now());
        crate::execution::execute(self, &record).await
    }

    async fn submit(&self, record: &Record, requested: SubmissionKind) -> anyhow::Result<Attempt> {
        let retained = self.journal.submissions(record.envelope.action).await?;
        // The journal returns hashes in key order, not attempt order. Once a rejection
        // transaction is durable, recovery must never return to executing gameplay.
        let mut attempts = Vec::new();
        for submission in retained {
            let transaction: BroadcastedInvokeTransaction = serde_json::from_slice(&submission.bytes)?;
            let fields = &transaction.broadcasted_invoke_txn_v3;
            let kind = SubmissionKind::from_selector(*fields.calldata.get(2).context("missing recorded selector")?)?;
            attempts.push(((kind == SubmissionKind::Reject, submission.epoch, fields.nonce), submission));
        }
        let Some((_, submission)) = attempts.into_iter().max_by_key(|(key, _)| *key) else {
            return self.prepare_submission(record, requested).await;
        };
        let transaction: BroadcastedInvokeTransaction = serde_json::from_slice(&submission.bytes)?;
        let fields = &transaction.broadcasted_invoke_txn_v3;
        let kind = SubmissionKind::from_selector(*fields.calldata.get(2).context("missing recorded selector")?)?;
        if kind == SubmissionKind::Execute
            && submission.refusal.as_deref().is_some_and(crate::execution::deterministic_limit)
        {
            return self.prepare_submission(record, SubmissionKind::Reject).await;
        }
        if requested == SubmissionKind::Reject && kind == SubmissionKind::Execute {
            return self.prepare_submission(record, requested).await;
        }
        // A fenced credential cannot submit or recover an old transport transaction.
        // The head was reconciled before reaching this path; retain only its ticket.
        if submission.epoch != self.config.epoch {
            return self.prepare_submission(record, kind).await;
        }
        match self.account.provider().get_transaction_status(submission.transaction_hash).await {
            Ok(status) => {
                if included_failure(&status) {
                    if kind == SubmissionKind::Execute {
                        return Ok(Attempt::Failed);
                    }
                    // Recording failed, not gameplay. Retry the rejection without changing the ticket.
                    return self.prepare_submission(record, kind).await;
                }
                return Ok(Attempt::Pending);
            }
            Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => {}
            Err(error) => return Err(error.into()),
        }
        // A changed authority nonce or epoch requires a new transport transaction, never a new ticket.
        if fields.nonce != self.account.get_nonce().await? {
            return self.prepare_submission(record, kind).await;
        }
        let (hash, expected) = self.prepare_transaction(record, fields.nonce, kind).await?;
        if hash != submission.transaction_hash || serde_json::to_vec(&transaction)? != serde_json::to_vec(&expected)? {
            bail!("retained transaction differs from its accepted binding");
        }
        self.broadcast(transaction, hash, kind).await
    }

    async fn prepare_submission(&self, record: &Record, kind: SubmissionKind) -> anyhow::Result<Attempt> {
        let started = Instant::now();
        let nonce = self.account.get_nonce().await?;
        let (hash, transaction) = self.prepare_transaction(record, nonce, kind).await?;
        self.journal.record_submission(record.envelope.action, hash, &serde_json::to_vec(&transaction)?).await?;
        let outcome = self.broadcast(transaction, hash, kind).await?;
        tracing::info!(target: "sequencer_randomness", action = %record.envelope.action.to_hex_string(),
            order = record.envelope.order, transaction = %hash.to_hex_string(),
            submission_ms = started.elapsed().as_secs_f64() * 1000.0, "randomness_submission");
        Ok(outcome)
    }

    async fn broadcast(
        &self,
        transaction: BroadcastedInvokeTransaction,
        hash: Felt,
        kind: SubmissionKind,
    ) -> anyhow::Result<Attempt> {
        match self.account.provider().add_invoke_transaction(transaction).await {
            Ok(received) => {
                if received.transaction_hash != hash {
                    bail!("submission hash mismatch");
                }
                Ok(Attempt::Pending)
            }
            Err(error) if kind == SubmissionKind::Execute && deterministic_refusal(&error) => {
                let reason = format!("{error:?}");
                let reason = crate::execution::limit_reason(&reason).context("missing deterministic refusal reason")?;
                self.journal.record_refusal(hash, reason).await?;
                Ok(Attempt::Failed)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn prepare_transaction(
        &self,
        record: &Record,
        nonce: Felt,
        kind: SubmissionKind,
    ) -> anyhow::Result<(Felt, BroadcastedInvokeTransaction)> {
        let calls = vec![Call {
            to: self.config.deployment,
            selector: kind.selector(),
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

impl ExecutionIo for Service {
    async fn outcome(&self, record: &Record) -> anyhow::Result<Observation> {
        let (order, timestamp, state) = self.head().await?;
        if order < record.envelope.order {
            return Ok(Observation::Unexecuted);
        }
        Ok(match self.result(record).await? {
            Some((progress, rejected)) => {
                if order == progress.order && (state != progress.state || timestamp != record.envelope.timestamp) {
                    // The receipt and head may straddle a pre-confirmation change. Reconcile again.
                    return Ok(Observation::Stale);
                }
                Observation::Recorded(progress, rejected)
            }
            None => Observation::Stale,
        })
    }

    async fn attempt(&self, record: &Record, kind: SubmissionKind) -> anyhow::Result<Attempt> {
        self.submit(record, kind).await
    }

    async fn complete(&self, record: &Record, progress: ChainProgress, rejected: bool) -> anyhow::Result<()> {
        Service::complete(self, record, progress, rejected).await
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
    if before.len() != 7 || after.len() != 7 {
        bail!("malformed native admission context");
    }
    Ok(before[..6] == after[..6] && admission_time_is_valid(intent, recorded, after[6].try_into()?))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn browser_preflight_and_rejections_keep_cors_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/actions", post(|| async { StatusCode::BAD_REQUEST }))
            .layer(middleware::from_fn(browser_access));
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        for (method, status) in [("OPTIONS", "204 No Content"), ("POST", "400 Bad Request")] {
            let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let request = format!("{method} /actions HTTP/1.1\r\nHost: {address}\r\nOrigin: https://play.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
            assert!(response.contains("access-control-allow-origin: *"));
            assert!(response.contains("access-control-allow-headers: content-type"));
            assert!(!response.contains("access-control-allow-credentials"));
        }
        server.abort();
    }

    #[tokio::test]
    async fn an_unregistered_key_cannot_reserve_another_players_slot() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/",
            post(|Json(request): Json<serde_json::Value>| async move {
                assert_eq!(request["method"], "starknet_call");
                Json(serde_json::json!({
                    "jsonrpc": "2.0", "id": request["id"],
                    "result": ["0x9", "0x1", "0x1", "0x0", "0x1", "0x0", "0x64"]
                }))
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let provider = JsonRpcClient::new(HttpTransport::new(format!("http://{address}").parse::<url::Url>().unwrap()));
        let intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::TWO,
            game: Felt::ONE,
            actor: Felt::from(3),
            nonce: 0,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 100,
            valid_until: 200,
            last_order: 10,
            arguments: vec![],
        };
        assert_eq!(verify_registered_actor(&provider, &intent, Felt::from(8)).await, Err(StatusCode::BAD_REQUEST));
        assert!(verify_registered_actor(&provider, &intent, Felt::from(9)).await.is_ok());
        server.abort();
    }

    #[test]
    fn request_signature_and_scope_are_checked_before_queueing_or_rpc() {
        let intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::TWO,
            game: Felt::ONE,
            actor: Felt::from(3),
            nonce: 0,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 100,
            valid_until: 200,
            last_order: 10,
            arguments: vec![],
        };
        let key = SigningKey::from_secret_scalar(Felt::from(12345));
        let signature = key.sign(&intent.identity().unwrap()).unwrap();
        let mut request = ActionRequest {
            intent: intent.encode().unwrap(),
            r: signature.r,
            s: signature.s,
            public_key: key.verifying_key().scalar(),
        };
        assert!(verify_request(&request, Felt::ONE, Felt::TWO).is_ok());
        assert!(verify_request(&request, Felt::TWO, Felt::TWO).is_err());
        assert!(verify_request(&request, Felt::ONE, Felt::ONE).is_err());
        request.r += Felt::ONE;
        assert!(verify_request(&request, Felt::ONE, Felt::TWO).is_err());
        request.r = signature.r;
        request.intent[6] += Felt::ONE;
        assert!(verify_request(&request, Felt::ONE, Felt::TWO).is_err());
    }

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
        let before = [Felt::ONE, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ONE, 1005u64.into()];
        let mut after = before;
        after[6] = 1010u64.into();
        assert!(admission_survived_external_checks(&intent, 1005, &before, &after).unwrap());
        after[6] = 1011u64.into();
        assert!(!admission_survived_external_checks(&intent, 1005, &before, &after).unwrap());
        for index in 0..6 {
            let mut changed = before;
            changed[index] += Felt::ONE;
            assert!(!admission_survived_external_checks(&intent, 1005, &before, &changed).unwrap());
        }
        assert!(admission_survived_external_checks(&intent, 1005, &before, &before[..6]).is_err());
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
    fn action_status_exposes_only_ticket_and_transaction_identity() {
        let pending = ActionStatus { action: Felt::ONE, order: 7, transaction_hash: None };
        assert_eq!(
            serde_json::to_value(pending).unwrap(),
            serde_json::json!({"action": "0x1", "order": 7, "transaction_hash": null})
        );
        let submitted = ActionStatus { action: Felt::ONE, order: 7, transaction_hash: Some(Felt::TWO) };
        assert_eq!(
            serde_json::to_value(submitted).unwrap(),
            serde_json::json!({"action": "0x1", "order": 7, "transaction_hash": "0x2"})
        );
    }

    #[test]
    fn admission_rejects_player_roots_context_and_transport_identity() {
        let request = serde_json::json!({"intent": [], "r": "0x1", "s": "0x2", "public_key": "0x3"});
        assert!(serde_json::from_value::<ActionRequest>(request.clone()).is_ok());
        for field in ["root", "context", "request_id", "transaction_hash", "authority_epoch"] {
            let mut altered = request.clone();
            altered[field] = serde_json::json!("0x1");
            assert!(serde_json::from_value::<ActionRequest>(altered).is_err());
        }
    }
}
