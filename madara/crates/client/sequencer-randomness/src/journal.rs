use crate::protocol::{decode_bytes, encode_bytes, Envelope, Intent, ProtocolError};
use crate::ticket::{Context, State, Ticket, TicketError};
use starknet_types_core::felt::Felt;
use std::collections::HashSet;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, IsolationLevel, NoTls, Row};

pub const SCHEMA: &str = concat!(include_str!("journal.sql"), include_str!("journal-lookup.sql"));

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal storage operation failed")]
    Storage(#[from] tokio_postgres::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error("journal prefix is missing, corrupt or inconsistent with chain progress")]
    Prefix,
    #[error("unresolved proposal: sampling ownership cannot be recreated")]
    UnresolvedProposal,
    #[error("authority epoch or order exceeds journal capacity")]
    Capacity,
    #[error("journal reader must be a physical standby")]
    Standby,
    #[error("invalid accepted player signature")]
    Signature,
}

/// The accepted gameplay key and its signature are retained outside action identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Authorization {
    pub public_key: Felt,
    pub r: Felt,
    pub s: Felt,
}

impl Authorization {
    fn verify(&self, action: Felt) -> Result<(), JournalError> {
        if matches!(starknet_crypto::verify(&self.public_key, &action, &self.r, &self.s), Ok(true)) {
            Ok(())
        } else {
            Err(JournalError::Signature)
        }
    }
}

pub struct Record {
    pub intent: Intent,
    pub envelope: Envelope,
    pub authorization: Authorization,
    pub result: Option<Felt>,
    pub following_state: Option<Felt>,
    pub rejected: Option<bool>,
    pub state: State,
}

impl Record {
    fn restore_ticket(self) -> Result<Ticket, TicketError> {
        Ticket::restore(self.intent, self.envelope, self.state, self.result)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainProgress {
    pub order: u64,
    pub binding: Felt,
    pub state: Felt,
    pub result: Felt,
}

pub struct Submission {
    pub action: Felt,
    pub transaction_hash: Felt,
    pub epoch: u64,
    pub bytes: Vec<u8>,
    pub refusal: Option<String>,
}

/// Local connections use private container networking or authenticated SSH tunnels.
/// The standby is the acknowledgement witness, never a primary-local retry read.
pub struct Journal {
    primary: Client,
    standby: Client,
    connections: Vec<JoinHandle<Result<(), tokio_postgres::Error>>>,
    epoch: i64,
}

impl Drop for Journal {
    fn drop(&mut self) {
        for connection in &self.connections {
            connection.abort();
        }
    }
}

impl Journal {
    pub async fn authorize_submission(
        &self,
        envelope: &Envelope,
        authorization: Authorization,
        transaction: Felt,
    ) -> Result<(), JournalError> {
        self.primary
            .query_one(
                "SELECT randomness.authorize_submission($1,$2,$3,$4,$5)",
                &[
                    &self.epoch,
                    &envelope.action.to_bytes_be().to_vec(),
                    &transaction.to_bytes_be().to_vec(),
                    &envelope.binding()?.to_bytes_be().to_vec(),
                    &encode_bytes(&[authorization.public_key, authorization.r, authorization.s]),
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn connect(primary: &str, standby: &str, epoch: u64) -> Result<Self, JournalError> {
        let epoch = i64::try_from(epoch).map_err(|_| JournalError::Capacity)?;
        let (primary, primary_connection) = tokio_postgres::connect(primary, NoTls).await?;
        let (standby, standby_connection) = tokio_postgres::connect(standby, NoTls).await?;
        let journal = Self {
            primary,
            standby,
            connections: vec![tokio::spawn(primary_connection), tokio::spawn(standby_connection)],
            epoch,
        };
        journal.require_standby().await?;
        Ok(journal)
    }

    pub async fn accept(
        &mut self,
        intent: Intent,
        context: Context,
        authorization: Authorization,
    ) -> Result<Record, JournalError> {
        let action = intent.identity()?;
        if let Some(record) = self.find_record(action).await? {
            return Ok(record);
        }
        context.validate(&intent)?;
        authorization.verify(action)?;
        let reserve_started = std::time::Instant::now();
        if !self.reserve_sampling(&intent, &context, authorization).await? {
            return self.accepted_record(action).await;
        }
        let reservation_ms = reserve_started.elapsed().as_secs_f64() * 1000.0;
        let sample_started = std::time::Instant::now();
        let mut ticket = Ticket::propose(intent, context)?;
        ticket.sample_os()?;
        let sampling_ms = sample_started.elapsed().as_secs_f64() * 1000.0;
        let commit_started = std::time::Instant::now();
        self.commit_binding(ticket.envelope_for_journal()?).await?;
        let commit_ms = commit_started.elapsed().as_secs_f64() * 1000.0;
        let witness_started = std::time::Instant::now();
        let record = self.accepted_record(action).await?;
        ticket.committed()?;
        if ticket.envelope()? != &record.envelope {
            return Err(JournalError::Prefix);
        }
        // Sampling timings are published only after the complete binding is acknowledged.
        tracing::info!(target: "sequencer_randomness", action = %action.to_hex_string(), order = record.envelope.order,
            reservation_ms, sampling_ms, commit_ms, witness_ms = witness_started.elapsed().as_secs_f64() * 1000.0,
            "randomness_journal");
        Ok(record)
    }

    async fn commit_binding(&self, envelope: &Envelope) -> Result<(), JournalError> {
        let bytes = encode_bytes(&envelope.encode()?);
        let binding = envelope.binding()?.to_bytes_be().to_vec();
        self.primary
            .query_one(
                "SELECT randomness.accept($1,$2,$3,$4)",
                &[&self.epoch, &envelope.action.to_bytes_be().to_vec(), &bytes, &binding],
            )
            .await?;
        Ok(())
    }

    async fn reserve_sampling(
        &self,
        intent: &Intent,
        context: &Context,
        authorization: Authorization,
    ) -> Result<bool, JournalError> {
        let action = intent.identity()?;
        let nonce = encode_bytes(&[intent.chain, intent.deployment, intent.game, intent.actor, intent.nonce.into()]);
        let signed = encode_bytes(&intent.encode()?);
        let auth = encode_bytes(&[authorization.public_key, authorization.r, authorization.s]);
        let order = i64::try_from(context.order).map_err(|_| JournalError::Capacity)?;
        let proposal = context_envelope(action, context);
        let context_bytes = encode_bytes(&proposal.encode()?[..9]);
        let id = action.to_bytes_be().to_vec();
        let created: bool = self
            .primary
            .query_one(
                "SELECT randomness.reserve($1,$2,$3,$4,$5,$6,$7)",
                &[&self.epoch, &nonce, &id, &order, &signed, &context_bytes, &auth],
            )
            .await?
            .get(0);
        Ok(created)
    }

    pub async fn record_submission(&self, action: Felt, transaction: Felt, bytes: &[u8]) -> Result<(), JournalError> {
        if transaction == Felt::ZERO || bytes.is_empty() {
            return Err(JournalError::Prefix);
        }
        self.accepted_record(action).await?.restore_ticket()?.submitted(transaction)?;
        self.primary
            .query_one(
                "SELECT randomness.record_submission($1,$2,$3,$4)",
                &[&self.epoch, &action.to_bytes_be().to_vec(), &transaction.to_bytes_be().to_vec(), &bytes],
            )
            .await?;
        Ok(())
    }

    pub async fn finish(
        &self,
        action: Felt,
        result: Felt,
        following_state: Felt,
        rejected: bool,
    ) -> Result<(), JournalError> {
        if result == Felt::ZERO {
            return Err(JournalError::Prefix);
        }
        self.accepted_record(action)
            .await?
            .restore_ticket()?
            .finish(if rejected { State::TerminalRejected } else { State::Executed }, result)?;
        self.primary
            .query_one(
                "SELECT randomness.finish($1,$2,$3,$4,$5)",
                &[
                    &self.epoch,
                    &action.to_bytes_be().to_vec(),
                    &result.to_bytes_be().to_vec(),
                    &following_state.to_bytes_be().to_vec(),
                    &rejected,
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn consume(&self, action: Felt) -> Result<(), JournalError> {
        self.accepted_record(action).await?.restore_ticket()?.consume()?;
        self.primary
            .query_one("SELECT randomness.consume($1,$2)", &[&self.epoch, &action.to_bytes_be().to_vec()])
            .await?;
        Ok(())
    }

    pub async fn recover(&mut self, chain: &[ChainProgress]) -> Result<Vec<Record>, JournalError> {
        self.require_standby().await?;
        let snapshot = self
            .standby
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let head = snapshot.query_one("SELECT * FROM randomness.head($1)", &[&self.epoch]).await?;
        let rows = snapshot.query("SELECT * FROM randomness.records($1)", &[&self.epoch]).await?;
        let records = rows.iter().map(decode_record).collect::<Result<Vec<_>, _>>()?;
        let completed = records.iter().take_while(|record| record.result.is_some()).count();
        let persisted_state = if completed == 0 {
            Felt::ZERO
        } else {
            records[completed - 1].following_state.ok_or(JournalError::Prefix)?
        };
        if head.get::<_, i64>("accepted_order") != records.len() as i64
            || head.get::<_, i64>("executed_order") != completed as i64
            || head.get::<_, i64>("executed_order") > chain.len() as i64
            || felt_bytes(head.get("state"))? != persisted_state
            || felt_bytes(head.get("binding"))?
                != records.last().map(|record| record.envelope.binding()).transpose()?.unwrap_or(Felt::ZERO)
        {
            return Err(JournalError::Prefix);
        }
        verify_prefix(&records, chain)?;
        snapshot.commit().await?;
        Ok(records)
    }

    pub async fn record_refusal(&self, transaction: Felt, reason: &str) -> Result<(), JournalError> {
        self.primary
            .query_one(
                "SELECT randomness.record_refusal($1,$2,$3)",
                &[&self.epoch, &transaction.to_bytes_be().to_vec(), &reason],
            )
            .await?;
        Ok(())
    }

    pub async fn submissions(&self, action: Felt) -> Result<Vec<Submission>, JournalError> {
        self.require_standby().await?;
        self.standby
            .query(
                "SELECT * FROM randomness.pending_submissions($1,$2)",
                &[&self.epoch, &action.to_bytes_be().to_vec()],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(Submission {
                    action: felt_bytes(row.get("action"))?,
                    transaction_hash: felt_bytes(row.get("transaction_hash"))?,
                    epoch: u64::try_from(row.get::<_, i64>("epoch")).map_err(|_| JournalError::Prefix)?,
                    bytes: row.get("transaction_bytes"),
                    refusal: row.get("refusal"),
                })
            })
            .collect()
    }

    pub async fn accepted_prefix(&self) -> Result<Vec<Record>, JournalError> {
        self.require_standby().await?;
        self.standby
            .query("SELECT * FROM randomness.records($1)", &[&self.epoch])
            .await?
            .iter()
            .map(decode_record)
            .collect()
    }

    async fn require_standby(&self) -> Result<(), JournalError> {
        let recovering: bool = self.standby.query_one("SELECT pg_is_in_recovery()", &[]).await?.get(0);
        if !recovering {
            return Err(JournalError::Standby);
        }
        Ok(())
    }

    async fn accepted_record(&self, action: Felt) -> Result<Record, JournalError> {
        self.find_record(action).await?.ok_or(JournalError::Prefix)
    }

    pub async fn find_record(&self, action: Felt) -> Result<Option<Record>, JournalError> {
        self.require_standby().await?;
        let row = self
            .standby
            .query_opt("SELECT * FROM randomness.records($1,$2)", &[&self.epoch, &action.to_bytes_be().to_vec()])
            .await?;
        row.as_ref().map(decode_record).transpose()
    }
}

fn context_envelope(action: Felt, context: &Context) -> Envelope {
    Envelope {
        action,
        order: context.order,
        predecessor: context.predecessor,
        preceding_state: context.preceding_state,
        timestamp: context.timestamp,
        execution_config: context.execution_config,
        l2_gas: context.l2_gas,
        root: [0; 32],
    }
}

fn context_from_envelope(envelope: &Envelope) -> Context {
    Context {
        order: envelope.order,
        predecessor: envelope.predecessor,
        preceding_state: envelope.preceding_state,
        timestamp: envelope.timestamp,
        execution_config: envelope.execution_config,
        l2_gas: envelope.l2_gas,
    }
}

fn felt_bytes(bytes: Vec<u8>) -> Result<Felt, JournalError> {
    let fields = decode_bytes(&bytes)?;
    if fields.len() != 1 {
        return Err(JournalError::Prefix);
    }
    Ok(fields[0])
}

fn decode_record(row: &Row) -> Result<Record, JournalError> {
    let encoded: Option<Vec<u8>> = row.get("envelope");
    let envelope = Envelope::decode(&decode_bytes(&encoded.ok_or(JournalError::UnresolvedProposal)?)?)?;
    let intent = Intent::decode(&decode_bytes(&row.get::<_, Vec<u8>>("intent"))?)?;
    let authorization = decode_bytes(&row.get::<_, Vec<u8>>("auth_witness"))?;
    if authorization.len() != 3
        || intent.identity()? != envelope.action
        || envelope.action != felt_bytes(row.get("action"))?
        || envelope.binding()? != felt_bytes(row.get("binding"))?
        || i64::try_from(envelope.order).map_err(|_| JournalError::Capacity)? != row.get::<_, i64>("ticket_order")
        || encode_bytes(&envelope.encode()?[..9]) != row.get::<_, Vec<u8>>("context")
        || encode_bytes(&[intent.chain, intent.deployment, intent.game, intent.actor, intent.nonce.into()])
            != row.get::<_, Vec<u8>>("nonce_key")
    {
        return Err(JournalError::Prefix);
    }
    context_from_envelope(&envelope).validate(&intent)?;
    let state = match row.get::<_, String>("status").as_str() {
        "committed" => State::Committed,
        "submitted" => State::Submitted,
        "executed" => State::Executed,
        "terminal-rejected" => State::TerminalRejected,
        "consumed" => State::Consumed,
        _ => return Err(JournalError::Prefix),
    };
    let authorization = Authorization { public_key: authorization[0], r: authorization[1], s: authorization[2] };
    authorization.verify(envelope.action)?;
    Ok(Record {
        intent,
        envelope,
        authorization,
        result: row.get::<_, Option<Vec<u8>>>("result").map(felt_bytes).transpose()?,
        following_state: row.get::<_, Option<Vec<u8>>>("following_state").map(felt_bytes).transpose()?,
        rejected: row.get("rejected"),
        state,
    })
}

pub fn verify_prefix(records: &[Record], chain: &[ChainProgress]) -> Result<(), JournalError> {
    if chain.len() > records.len() {
        return Err(JournalError::Prefix);
    }
    let mut predecessor = Felt::ZERO;
    let mut state = Felt::ZERO;
    let mut nonces = HashSet::new();
    for (index, record) in records.iter().enumerate() {
        let envelope = &record.envelope;
        let intent = &record.intent;
        if envelope.order != index as u64 + 1
            || envelope.predecessor != predecessor
            || envelope.preceding_state != state
            || envelope.action != intent.identity()?
            || !nonces.insert([intent.chain, intent.deployment, intent.game, intent.actor, intent.nonce.into()])
        {
            return Err(JournalError::Prefix);
        }
        let binding = envelope.binding()?;
        if let Some(progress) = chain.get(index) {
            if progress.order != envelope.order
                || progress.binding != binding
                || record.result.is_some_and(|result| progress.result != result)
                || record.following_state.is_some_and(|following| progress.state != following)
            {
                return Err(JournalError::Prefix);
            }
            state = progress.state;
        } else if record.result.is_some() || record.state == State::Consumed || index + 1 != records.len() {
            return Err(JournalError::Prefix);
        }
        predecessor = binding;
    }
    Ok(())
}
