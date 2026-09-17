use crate::{
    journal::{Authorization, Journal},
    protocol::{Envelope, Intent},
    service::{required, Configuration},
};
use anyhow::{bail, Context};
use starknet_core::utils::get_selector_from_name;
use starknet_types_core::felt::Felt;

pub struct SubmissionGate {
    pub account: Felt,
    deployment: Felt,
    chain: Felt,
    epoch: u64,
    primary: String,
    standby: String,
    journal: Option<Journal>,
    worker: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    refusals: tokio::sync::mpsc::Sender<(Felt, &'static str)>,
    refusal_worker: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionKind {
    Execute,
    Reject,
}

impl SubmissionKind {
    pub(crate) fn selector(self) -> Felt {
        get_selector_from_name(match self {
            Self::Execute => "execute",
            Self::Reject => "reject_execution",
        })
        .expect("static selector")
    }

    pub(crate) fn from_selector(selector: Felt) -> anyhow::Result<Self> {
        for kind in [Self::Execute, Self::Reject] {
            if selector == kind.selector() {
                return Ok(kind);
            }
        }
        bail!("only recorded execution or rejection is allowed")
    }
}

pub struct Execution {
    pub intent: Intent,
    pub envelope: Envelope,
    pub epoch: u64,
    pub accepted_public_key: Felt,
    pub r: Felt,
    pub s: Felt,
}

/// Only the executor can report a deterministic refusal; an absent report never implies failure.
#[derive(Debug)]
pub struct RefusalReporter {
    transaction: Felt,
    sender: tokio::sync::mpsc::Sender<(Felt, &'static str)>,
}

impl RefusalReporter {
    pub fn report(self, reason: &str) {
        if let Some(reason) = crate::execution::limit_reason(reason) {
            if self.sender.try_send((self.transaction, reason)).is_err() {
                tracing::warn!(target: "sequencer_randomness", transaction = %self.transaction,
                    "refusal recording queue unavailable; ticket remains pending for reconciliation");
            }
        }
    }
}

impl SubmissionGate {
    pub fn from_env(chain: Felt) -> anyhow::Result<Self> {
        let config = Configuration::from_env()?;
        let worker = match required("RANDOMNESS_PLACEMENT")?.as_str() {
            "embedded" => Some(tokio::spawn(crate::service::run())),
            "sidecar" => None,
            _ => bail!("RANDOMNESS_PLACEMENT must be embedded or sidecar"),
        };
        let (refusals, receiver) = tokio::sync::mpsc::channel(64);
        let refusal_worker =
            tokio::spawn(record_refusals(config.primary.clone(), config.standby.clone(), config.epoch, receiver));
        Ok(Self {
            account: config.account,
            deployment: config.deployment,
            chain,
            epoch: config.epoch,
            primary: config.primary,
            standby: config.standby,
            journal: None,
            worker,
            refusals,
            refusal_worker,
        })
    }

    pub fn refusal_reporter(&self, transaction: Felt) -> RefusalReporter {
        RefusalReporter { transaction, sender: self.refusals.clone() }
    }

    pub async fn authorize(&mut self, hash: Felt, calldata: &[Felt], l2_gas: u64, query: bool) -> anyhow::Result<()> {
        let started = std::time::Instant::now();
        if self.worker.as_ref().is_some_and(|worker| worker.is_finished()) {
            bail!("embedded admission worker stopped; recovery required");
        }
        if query {
            bail!("query cannot enter recorded execution");
        }
        let execution = decode_execution(calldata, self.deployment)?;
        if execution.epoch != self.epoch
            || execution.envelope.l2_gas != l2_gas
            || execution.intent.chain != self.chain
            || execution.intent.deployment != self.deployment
        {
            bail!("recorded submission context mismatch");
        }
        if self.journal.is_none() {
            self.journal = Some(Journal::connect(&self.primary, &self.standby, self.epoch).await?);
        }
        self.journal
            .as_ref()
            .context("journal initialization")?
            .authorize_submission(
                &execution.envelope,
                Authorization { public_key: execution.accepted_public_key, r: execution.r, s: execution.s },
                hash,
            )
            .await?;
        tracing::info!(target: "sequencer_randomness", action = %execution.envelope.action.to_hex_string(),
            order = execution.envelope.order, transaction = %hash.to_hex_string(),
            checks_ms = started.elapsed().as_secs_f64() * 1000.0, "randomness_submission_checks");
        Ok(())
    }
}

impl Drop for SubmissionGate {
    fn drop(&mut self) {
        self.refusal_worker.abort();
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

async fn record_refusals(
    primary: String,
    standby: String,
    epoch: u64,
    mut receiver: tokio::sync::mpsc::Receiver<(Felt, &'static str)>,
) {
    while let Some((transaction, reason)) = receiver.recv().await {
        loop {
            let result =
                async { Journal::connect(&primary, &standby, epoch).await?.record_refusal(transaction, reason).await }
                    .await;
            match result {
                Ok(()) => break,
                Err(error) => {
                    tracing::warn!(target: "sequencer_randomness", %transaction, %error,
                        "executor refusal awaiting durable recording");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}

pub fn execution_calldata(
    intent: &Intent,
    envelope: &Envelope,
    authorization: Authorization,
    epoch: u64,
) -> anyhow::Result<Vec<Felt>> {
    if envelope.action != intent.identity()? {
        bail!("action binding mismatch");
    }
    let mut payload = intent.encode()?[2..].to_vec();
    let encoded = envelope.encode()?;
    payload.push(Felt::from(encoded.len() as u64));
    payload.extend(encoded);
    payload.extend([epoch.into(), authorization.public_key, authorization.r, authorization.s]);
    Ok(payload)
}

/// Standard single-call account encoding followed by execute(intent, context, r, s).
pub fn decode_execution(calldata: &[Felt], deployment: Felt) -> anyhow::Result<Execution> {
    if calldata.len() < 4 || calldata[0] != Felt::ONE || calldata[1] != deployment {
        bail!("only one native execute call is allowed");
    }
    SubmissionKind::from_selector(calldata[2])?;
    let payload_length = usize::try_from(calldata[3]).context("invalid execute length")?;
    let payload = &calldata[4..];
    if payload.len() != payload_length || payload.len() < 11 {
        bail!("malformed execute calldata");
    }
    let argument_count = usize::try_from(payload[10]).context("invalid argument count")?;
    if argument_count > 256 {
        bail!("too many action arguments");
    }
    let intent_length = 11 + argument_count;
    if payload.len() != intent_length + 15 || payload[intent_length] != Felt::from(10) {
        bail!("malformed recorded context");
    }
    let mut fields = vec![Felt::from_bytes_be_slice(b"ETERNUM_ACTION"), Felt::ONE];
    fields.extend_from_slice(&payload[..intent_length]);
    let intent = Intent::decode(&fields)?;
    let envelope = Envelope::decode(&payload[intent_length + 1..intent_length + 11])?;
    if envelope.action != intent.identity()? {
        bail!("action binding mismatch");
    }
    Ok(Execution {
        intent,
        envelope,
        epoch: payload[intent_length + 11].try_into().context("invalid authority epoch")?,
        accepted_public_key: payload[intent_length + 12],
        r: payload[intent_length + 13],
        s: payload[intent_length + 14],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call() -> Vec<Felt> {
        let intent = Intent {
            chain: Felt::ONE,
            deployment: Felt::TWO,
            game: Felt::THREE,
            actor: Felt::ONE,
            nonce: 0,
            command: Felt::ONE,
            rules: Felt::ONE,
            valid_from: 1000,
            valid_until: 1010,
            last_order: 10,
            arguments: vec![Felt::ONE, Felt::TWO],
        };
        let envelope = Envelope {
            action: intent.identity().unwrap(),
            order: 1,
            preceding_state: Felt::ZERO,
            timestamp: 1005,
            execution_config: Felt::ONE,
            l2_gas: 1_200_000_000,
            root: [255; 32],
        };
        let payload = execution_calldata(
            &intent,
            &envelope,
            Authorization { public_key: Felt::ONE, r: Felt::TWO, s: Felt::THREE },
            1,
        )
        .unwrap();
        let mut call =
            vec![Felt::ONE, Felt::TWO, get_selector_from_name("execute").unwrap(), Felt::from(payload.len() as u64)];
        call.extend(payload);
        call
    }

    #[test]
    fn refusal_reporting_is_bounded_and_ignores_transient_errors() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        RefusalReporter { transaction: Felt::ONE, sender: sender.clone() }.report("queue full");
        assert!(receiver.try_recv().is_err());
        RefusalReporter { transaction: Felt::ONE, sender: sender.clone() }
            .report("Exceeded the maximum number of events, number events: 1001, max number events: 1000.");
        // A saturated reporting queue never blocks the executor or invents an outcome.
        RefusalReporter { transaction: Felt::TWO, sender }
            .report("Exceeded the maximum data length, data length: 301, max data length: 300.");
        assert_eq!(receiver.try_recv().unwrap(), (Felt::ONE, "Exceeded the maximum number of events,"));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn rejection_transport_retains_the_original_ticket_and_witnesses() {
        let original = call();
        let mut rejection = original.clone();
        rejection[2] = SubmissionKind::Reject.selector();
        let executed = decode_execution(&original, Felt::TWO).unwrap();
        let rejected = decode_execution(&rejection, Felt::TWO).unwrap();
        assert!(executed.envelope == rejected.envelope);
        assert_eq!(executed.intent.encode().unwrap(), rejected.intent.encode().unwrap());
        assert_eq!((executed.r, executed.s), (rejected.r, rejected.s));
    }

    #[test]
    fn execution_transport_retains_intent_context_root_and_witnesses() {
        let execution = decode_execution(&call(), Felt::TWO).unwrap();
        assert_eq!(execution.envelope.root, [255; 32]);
        assert_eq!(execution.envelope.action, execution.intent.identity().unwrap());
        assert_eq!(execution.epoch, 1);
        assert_eq!((execution.accepted_public_key, execution.r, execution.s), (Felt::ONE, Felt::TWO, Felt::THREE));
    }

    #[test]
    fn execution_transport_rejects_multicalls_malformed_envelopes_and_argument_substitution() {
        let original = call();
        for length in 0..original.len() {
            assert!(decode_execution(&original[..length], Felt::TWO).is_err());
        }
        let mut extra = original.clone();
        extra.push(Felt::ZERO);
        assert!(decode_execution(&extra, Felt::TWO).is_err());
        for position in [0, 1, 2, 3, 4, 14, 15, 18, 19, 21, 26] {
            let mut changed = original.clone();
            changed[position] = Felt::MAX;
            assert!(decode_execution(&changed, Felt::TWO).is_err(), "position {position}");
        }
    }
}
