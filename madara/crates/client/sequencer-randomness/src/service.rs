use crate::{
    admission::{AdmissionSlots, IpLimits, Permit, Slot},
    epoch::EpochSecret,
    execution::{self, PendingTicket},
    node::{Execution, Node},
    protocol::{Envelope, Intent},
    settlement::SettlementChecks,
    submission::ExecutionObservers,
    ticket::{context_matches, ActionRequest, ActionStatus, RecordedTicket},
};
use anyhow::{ensure, Context};
use futures::{future::BoxFuture, FutureExt};
use jsonrpsee::{types::ErrorObjectOwned, RpcModule, SubscriptionMessage};
use mc_db::MadaraBackend;
use mc_mempool::Mempool;
use mc_submit_tx::SubmitTransaction;
use mp_convert::ToFelt;
use mp_receipt::ExecutionResult;
use mp_utils::service::{MadaraServiceId, PowerOfTwo, Service, ServiceId, ServiceRunner};
use starknet_signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

const QUEUE_CAPACITY: usize = 128;
const MAX_BATCH: usize = 16;
const PACK_DELAY: Duration = Duration::from_millis(10);
const EPOCH_ORDERS: u64 = 100_000;

struct Request {
    intent: Intent,
    signature: [Felt; 2],
    public_key: Felt,
    permit: Permit,
    received: Instant,
}

struct Shared {
    node: Arc<Node>,
    slots: AdmissionSlots,
    sender: Mutex<Option<mpsc::Sender<Request>>>,
    ip_limits: Mutex<IpLimits>,
}

#[derive(Clone)]
pub struct GameApi(Arc<Shared>);
impl std::fmt::Debug for GameApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GameApi")
    }
}

impl GameApi {
    async fn admit(&self, peer: IpAddr, action: ActionRequest) -> anyhow::Result<watch::Receiver<ActionStatus>> {
        ensure!(
            self.0.ip_limits.lock().expect("admission limiter poisoned").allow(peer, Instant::now()),
            "request rate exceeded"
        );
        let node = &self.0.node;
        let intent = action.verify(node.backend.chain_config().chain_id.clone().to_felt(), node.deployment)?;
        let digest = intent.identity()?;
        // An attacker signing with their own key cannot occupy another actor's slot.
        let fields = node.world_view("get_admission", vec![intent.game, intent.actor]).await?;
        let [key, _, _, nonce, _, _] = fields.as_slice() else { anyhow::bail!("malformed admission view") };
        ensure!(*key == action.public_key, "unregistered gameplay key");
        if *nonce != Felt::from(intent.nonce) {
            if *nonce > Felt::from(intent.nonce) {
                if let Some(outcome) = node.recorded_action(&intent).await? {
                    return Ok(watch::channel(outcome).1);
                }
            }
            anyhow::bail!("actor nonce is not current; no matching action in reconnect history");
        }
        match self.0.slots.reserve(intent.actor, digest).map_err(anyhow::Error::msg)? {
            Slot::Existing(receiver) => Ok(receiver),
            Slot::New(permit) => {
                let receiver = permit.subscribe();
                let sender = self
                    .0
                    .sender
                    .lock()
                    .expect("admission sender poisoned")
                    .clone()
                    .context("game admission is unavailable")?;
                sender
                    .try_send(Request {
                        intent,
                        signature: [action.r, action.s],
                        public_key: action.public_key,
                        permit,
                        received: Instant::now(),
                    })
                    .map_err(|_| anyhow::anyhow!("game admission queue is full or unavailable"))?;
                Ok(receiver)
            }
        }
    }

    /// The peer comes from the node's TCP connection, never a client-controlled header.
    pub fn rpc(&self, peer: IpAddr) -> anyhow::Result<RpcModule<Self>> {
        let mut module = RpcModule::new(self.clone());
        module.register_subscription(
            "game_V0_10_2_subscribeAction",
            "game_action",
            "game_V0_10_2_unsubscribeAction",
            move |params, pending, api| async move {
                let action = match params.one::<ActionRequest>() {
                    Ok(action) => action,
                    Err(error) => {
                        pending.reject(error).await;
                        return Ok(());
                    }
                };
                let mut updates = match api.admit(peer, action).await {
                    Ok(updates) => updates,
                    Err(error) => {
                        pending.reject(ErrorObjectOwned::owned(-32001, error.to_string(), None::<()>)).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                loop {
                    let status = updates.borrow_and_update().clone();
                    sink.send(SubscriptionMessage::from_json(&status)?).await?;
                    if status.is_final() {
                        break;
                    }
                    tokio::select! {
                        _ = sink.closed() => break,
                        changed = updates.changed() => { if changed.is_err() { break; } }
                    }
                }
                Ok(())
            },
        )?;
        module.register_async_method("game_V0_10_2_rotateGameplayKey", move |params, api| async move {
            let transaction = params.one::<mp_rpc::v0_10_2::BroadcastedInvokeTxn>()?;
            let ready = api.0.sender.lock().expect("admission sender poisoned").is_some();
            if !ready {
                return Err(ErrorObjectOwned::owned(-32001, "game admission unavailable", None::<()>));
            }
            crate::key_rotation::submit(&api.0.node, &api.0.slots, transaction)
                .await
                .map_err(|error| ErrorObjectOwned::owned(-32001, error.to_string(), None::<()>))
        })?;
        Ok(module)
    }
}

pub struct GameService {
    api: GameApi,
    settlement: Arc<SettlementChecks>,
    secret_path: PathBuf,
}

impl GameService {
    pub fn from_env(
        backend: Arc<MadaraBackend>,
        mempool: Arc<Mempool>,
        submit: Arc<dyn SubmitTransaction>,
        observers: ExecutionObservers,
    ) -> anyhow::Result<Self> {
        let node = Arc::new(Node {
            backend,
            mempool,
            submit,
            observers,
            deployment: Felt::from_hex(&required("RANDOMNESS_DEPLOYMENT")?)?,
            key: SigningKey::from_secret_scalar(Felt::from_hex(&required("RANDOMNESS_PRIVATE_KEY")?)?),
            l2_gas: 1_200_000_000,
        });
        let schema = std::fs::read_to_string(required("RANDOMNESS_NATIVE_SCHEMA")?)?;
        let l2 = std::env::var("RANDOMNESS_L2_RPC_URL").ok().filter(|url| !url.is_empty());
        let settlement = Arc::new(SettlementChecks::load(&schema, l2.as_deref())?);
        let api = GameApi(Arc::new(Shared {
            node,
            slots: AdmissionSlots::default(),
            sender: Mutex::new(None),
            ip_limits: Mutex::new(IpLimits::default()),
        }));
        Ok(Self { api, settlement, secret_path: PathBuf::from(required("RANDOMNESS_EPOCH_SECRET")?) })
    }
    pub fn api(&self) -> GameApi {
        self.api.clone()
    }
}

pub fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("missing {name}"))
}

#[async_trait::async_trait]
impl Service for GameService {
    async fn start<'a>(&mut self, runner: ServiceRunner<'a>) -> anyhow::Result<()> {
        let api = self.api.clone();
        let settlement = self.settlement.clone();
        let secret_path = self.secret_path.clone();
        runner.service_loop(move |mut ctx| async move {
            let result = ctx.run_until_cancelled(run(api.clone(), settlement, secret_path)).await;
            api.0.sender.lock().expect("admission sender poisoned").take();
            if let Some(Err(error)) = result {
                // Game admission can fail closed without stopping ordinary block production.
                tracing::error!(target: "sequencer_randomness", %error, "game admission paused; restart after correcting the reported state");
                ctx.cancelled().await;
            }
            Ok::<(), anyhow::Error>(())
        });
        Ok(())
    }
}
impl ServiceId for GameService {
    fn svc_id(&self) -> PowerOfTwo {
        MadaraServiceId::GameSequencing.svc_id()
    }
}

async fn run(api: GameApi, settlement: Arc<SettlementChecks>, path: PathBuf) -> anyhow::Result<()> {
    let node = api.0.node.clone();
    let mut tip = node.backend.watch_chain_head_state();
    while node.backend.view_on_latest().get_contract_class_hash(&node.deployment)?.is_none()
        || node.backend.view_on_latest().get_contract_class_hash(&node.observers.account)?.is_none()
    {
        tip.recv().await;
    }
    node.drain_retained().await?;
    let mut epoch = prepare_epoch(&node, &path).await?;
    let mut order = node.head().await?.0 + 1;
    let (sender, mut requests) = mpsc::channel(QUEUE_CAPACITY);
    *api.0.sender.lock().expect("admission sender poisoned") = Some(sender);
    let mut queue = Vec::new();
    let mut flight: Option<BoxFuture<'static, anyhow::Result<()>>> = None;
    let mut deadline = tokio::time::Instant::now() + PACK_DELAY;
    loop {
        if flight.is_none()
            && !queue.is_empty()
            && (queue.len() >= MAX_BATCH || tokio::time::Instant::now() >= deadline)
        {
            flight = Some(execution::execute(node.clone(), std::mem::take(&mut queue)).boxed());
        }
        if flight.is_none() && queue.is_empty() && order > epoch.last_order {
            epoch = prepare_epoch(&node, &path).await?;
        }
        tokio::select! {
            request = requests.recv(), if queue.len() < MAX_BATCH && order <= epoch.last_order => {
                let request = request.context("game request queue closed")?;
                let action = request.intent.identity()?;
                match accept(&node, &settlement, &epoch, order, &request).await {
                    Ok(record) => {
                        request.permit.resolve(ActionStatus::Accepted { action, order });
                        tracing::debug!(target: "sequencer_randomness", %action, order,
                            admission_ms = request.received.elapsed().as_secs_f64() * 1000.0, "game_action_accepted");
                        if queue.is_empty() { deadline = tokio::time::Instant::now() + PACK_DELAY; }
                        queue.push(PendingTicket { record, permit: request.permit });
                        order += 1;
                    }
                    Err(error) => request.permit.resolve(ActionStatus::Refused { action, reason: error.to_string() }),
                }
            }
            result = async { flight.as_mut().expect("flight branch enabled").await }, if flight.is_some() => {
                result?;
                flight = None;
            }
            _ = tokio::time::sleep_until(deadline), if flight.is_none() && !queue.is_empty() => {}
        }
    }
}

async fn accept(
    node: &Node,
    settlement: &SettlementChecks,
    epoch: &EpochSecret,
    order: u64,
    request: &Request,
) -> anyhow::Result<RecordedTicket> {
    let intent = &request.intent;
    let fields = node.world_view("get_admission", vec![intent.game, intent.actor]).await?;
    let [key, rules, config, nonce, _, observed_time] = fields.as_slice() else {
        anyhow::bail!("malformed admission view")
    };
    ensure!(
        *key == request.public_key && *rules == intent.rules && *nonce == Felt::from(intent.nonce),
        "admission state changed"
    );
    let timestamp = node.timestamp()?;
    let now: u64 = (*observed_time).try_into()?;
    ensure!(context_matches(intent, order, timestamp) && now <= intent.valid_until, "intent expired before acceptance");
    if settlement.is_settlement(intent) {
        let policy = node.world_view("settlement_admission", vec![intent.game, intent.actor]).await?;
        ensure!(settlement.verify(intent, &policy).await?, "settlement admission rejected");
        let current = node.world_view("get_admission", vec![intent.game, intent.actor]).await?;
        ensure!(current.get(..4) == fields.get(..4), "actor changed during settlement checks");
        let now: u64 = (*current.get(5).context("missing admission timestamp")?).try_into()?;
        ensure!(now <= intent.valid_until, "intent expired during settlement checks");
    }
    Ok(RecordedTicket {
        intent: intent.clone(),
        envelope: Envelope {
            action: intent.identity()?,
            order,
            timestamp,
            execution_config: *config,
            root: epoch.root(order)?,
        },
        r: request.signature[0],
        s: request.signature[1],
    })
}

async fn prepare_epoch(node: &Node, path: &std::path::Path) -> anyhow::Result<EpochSecret> {
    let (head, _, _) = node.head().await?;
    let account = node.observers.account;
    let current = node.view(account, "current_randomness_epoch", vec![]).await?;
    let [id] = current.as_slice() else { anyhow::bail!("malformed current epoch") };
    if *id != Felt::ZERO {
        let epoch = node.view(account, "get_randomness_epoch", vec![*id]).await?;
        let [first, last, commitment, revealed, ..] = epoch.as_slice() else {
            anyhow::bail!("malformed randomness epoch")
        };
        if *revealed == Felt::ONE {
            let secret = EpochSecret::load(path)?;
            ensure!(
                secret.commitment() == *commitment
                    && Felt::from(secret.first_order) == *first
                    && Felt::from(secret.last_order) == *last,
                "epoch secret does not match chain commitment"
            );
            if head < secret.last_order {
                return Ok(secret);
            }
            ensure!(head == secret.last_order, "execution head exceeds unrevealed epoch");
            epoch_command(node, "reveal_randomness_epoch", secret.reveal().to_vec()).await?;
        }
    }
    let secret = if path.exists() {
        let candidate = EpochSecret::load(path)?;
        if candidate.first_order == head + 1 {
            candidate
        } else {
            EpochSecret::create(head + 1, head.checked_add(EPOCH_ORDERS).context("epoch order overflow")?)?
        }
    } else {
        EpochSecret::create(head + 1, head.checked_add(EPOCH_ORDERS).context("epoch order overflow")?)?
    };
    secret.save(path)?;
    epoch_command(node, "open_randomness_epoch", vec![secret.commitment(), secret.last_order.into()]).await?;
    Ok(secret)
}

async fn epoch_command(node: &Node, name: &'static str, payload: Vec<Felt>) -> anyhow::Result<()> {
    let (hash, transaction) = node.prepare(node.observers.account, name, payload)?;
    match node.execute(hash, transaction).await? {
        Execution::Included(receipt) if receipt.execution_result() == ExecutionResult::Succeeded => Ok(()),
        _ => anyhow::bail!("randomness epoch transition failed"),
    }
}
