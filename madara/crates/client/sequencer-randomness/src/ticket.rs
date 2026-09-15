use crate::protocol::{Envelope, Intent, ProtocolError};
use starknet_types_core::felt::Felt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Proposed,
    Committed,
    Submitted,
    Executed,
    TerminalRejected,
    Consumed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TicketError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("acceptance context is outside signed limits")]
    Context,
    #[error("entropy sampling was already attempted")]
    AlreadySampled,
    #[error("initialized operating-system entropy source failed")]
    Entropy,
    #[error("ticket has not committed")]
    Uncommitted,
    #[error("invalid ticket transition")]
    Transition,
    #[error("conflicting result")]
    ConflictingResult,
}

/// No root is present in a proposal's execution context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub order: u64,
    pub predecessor: Felt,
    pub preceding_state: Felt,
    pub timestamp: u64,
    pub execution_config: Felt,
    pub l2_gas: u64,
}

impl Context {
    pub fn validate(&self, intent: &Intent) -> Result<(), TicketError> {
        intent.encode()?;
        if self.order == 0
            || self.order > intent.last_order
            || self.timestamp < intent.valid_from
            || self.timestamp > intent.valid_until
            || self.l2_gas == 0
        {
            return Err(TicketError::Context);
        }
        Ok(())
    }
}

pub fn timestamp_in_bounds(recorded: u64, block_time: u64) -> bool {
    recorded <= block_time
}

/// The journal must persist exclusive sampling ownership before invoking `sample_os`.
/// This value is deliberately neither Clone nor Debug: a proposal cannot become a second sampler or a log record.
pub struct Ticket {
    intent: Intent,
    context: Context,
    state: State,
    sampling_attempted: bool,
    envelope: Option<Envelope>,
    submissions: Vec<Felt>,
    result: Option<Felt>,
}

impl Ticket {
    pub(crate) fn restore(
        intent: Intent,
        envelope: Envelope,
        state: State,
        result: Option<Felt>,
    ) -> Result<Self, TicketError> {
        if state == State::Proposed
            || matches!(state, State::Executed | State::TerminalRejected | State::Consumed) != result.is_some()
            || envelope.action != intent.identity()?
        {
            return Err(TicketError::Transition);
        }
        let context = Context {
            order: envelope.order,
            predecessor: envelope.predecessor,
            preceding_state: envelope.preceding_state,
            timestamp: envelope.timestamp,
            execution_config: envelope.execution_config,
            l2_gas: envelope.l2_gas,
        };
        context.validate(&intent)?;
        Ok(Self {
            intent,
            context,
            state,
            sampling_attempted: true,
            envelope: Some(envelope),
            submissions: Vec::new(),
            result,
        })
    }

    pub fn propose(intent: Intent, context: Context) -> Result<Self, TicketError> {
        context.validate(&intent)?;
        Ok(Self {
            intent,
            context,
            state: State::Proposed,
            sampling_attempted: false,
            envelope: None,
            submissions: Vec::new(),
            result: None,
        })
    }

    pub fn sample_os(&mut self) -> Result<(), TicketError> {
        self.sample_with(|root| {
            let read = rustix::rand::getrandom(&mut root[..], rustix::rand::GetRandomFlags::empty())
                .map_err(|_| TicketError::Entropy)?;
            if read != root.len() {
                return Err(TicketError::Entropy);
            }
            Ok(())
        })
    }

    fn sample_with(&mut self, fill: impl FnOnce(&mut [u8; 32]) -> Result<(), TicketError>) -> Result<(), TicketError> {
        if self.sampling_attempted {
            return Err(TicketError::AlreadySampled);
        }
        if self.state != State::Proposed {
            return Err(TicketError::Transition);
        }
        // Set before calling the source, including on error or unwind. The durable claim survives process loss.
        self.sampling_attempted = true;
        let mut root = [0; 32];
        fill(&mut root)?;
        self.envelope = Some(Envelope {
            action: self.intent.identity()?,
            order: self.context.order,
            predecessor: self.context.predecessor,
            preceding_state: self.context.preceding_state,
            timestamp: self.context.timestamp,
            execution_config: self.context.execution_config,
            l2_gas: self.context.l2_gas,
            root,
        });
        Ok(())
    }

    /// Called only after the journal acknowledges durable replication of this exact envelope.
    pub fn committed(&mut self) -> Result<(), TicketError> {
        if self.state != State::Proposed || self.envelope.is_none() {
            return Err(TicketError::Transition);
        }
        self.state = State::Committed;
        Ok(())
    }

    pub(crate) fn envelope_for_journal(&self) -> Result<&Envelope, TicketError> {
        self.envelope.as_ref().ok_or(TicketError::Uncommitted)
    }

    pub fn envelope(&self) -> Result<&Envelope, TicketError> {
        if self.state == State::Proposed {
            return Err(TicketError::Uncommitted);
        }
        self.envelope.as_ref().ok_or(TicketError::Uncommitted)
    }

    pub fn submitted(&mut self, transaction: Felt) -> Result<(), TicketError> {
        if !matches!(self.state, State::Committed | State::Submitted) || transaction == Felt::ZERO {
            return Err(TicketError::Transition);
        }
        if !self.submissions.contains(&transaction) {
            self.submissions.push(transaction);
        }
        self.state = State::Submitted;
        Ok(())
    }

    pub fn finish(&mut self, outcome: State, result: Felt) -> Result<(), TicketError> {
        if !matches!(outcome, State::Executed | State::TerminalRejected) || result == Felt::ZERO {
            return Err(TicketError::Transition);
        }
        if self.state == outcome {
            return if self.result == Some(result) { Ok(()) } else { Err(TicketError::ConflictingResult) };
        }
        if self.state != State::Submitted {
            return Err(TicketError::Transition);
        }
        self.result = Some(result);
        self.state = outcome;
        Ok(())
    }

    pub fn consume(&mut self) -> Result<(), TicketError> {
        if !matches!(self.state, State::Executed | State::TerminalRejected | State::Consumed) {
            return Err(TicketError::Transition);
        }
        self.state = State::Consumed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal() -> Ticket {
        Ticket::propose(
            Intent {
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
                arguments: vec![],
            },
            Context {
                order: 1,
                predecessor: Felt::ZERO,
                preceding_state: Felt::ZERO,
                timestamp: 1005,
                execution_config: Felt::ONE,
                l2_gas: 1_200_000_000,
            },
        )
        .unwrap()
    }

    fn sampled() -> Ticket {
        let mut ticket = proposal();
        ticket
            .sample_with(|root| {
                *root = [255; 32];
                Ok(())
            })
            .unwrap();
        ticket
    }

    #[test]
    fn root_is_hidden_until_commit_and_preserved_through_both_terminal_paths() {
        for outcome in [State::Executed, State::TerminalRejected] {
            let mut ticket = sampled();
            assert!(matches!(ticket.envelope(), Err(TicketError::Uncommitted)));
            ticket.committed().unwrap();
            let binding = ticket.envelope().unwrap().binding().unwrap();
            assert_eq!(ticket.envelope().unwrap().root, [255; 32]);
            for transaction in [Felt::ONE, Felt::ONE, Felt::TWO] {
                ticket.submitted(transaction).unwrap();
            }
            assert_eq!(ticket.submissions, vec![Felt::ONE, Felt::TWO]);
            ticket.finish(outcome, Felt::THREE).unwrap();
            ticket.finish(outcome, Felt::THREE).unwrap();
            assert_eq!(ticket.finish(outcome, Felt::ONE), Err(TicketError::ConflictingResult));
            ticket.consume().unwrap();
            ticket.consume().unwrap();
            assert_eq!(ticket.state, State::Consumed);
            assert_eq!(ticket.envelope().unwrap().binding().unwrap(), binding);
            assert_eq!(ticket.sample_os(), Err(TicketError::AlreadySampled));
        }
    }

    #[test]
    fn recovery_at_every_accepted_state_keeps_the_binding_and_cannot_sample() {
        let original = sampled();
        let envelope = original.envelope_for_journal().unwrap().clone();
        for state in [State::Committed, State::Submitted, State::Executed, State::TerminalRejected, State::Consumed] {
            let result =
                matches!(state, State::Executed | State::TerminalRejected | State::Consumed).then_some(Felt::THREE);
            let mut recovered = Ticket::restore(original.intent.clone(), envelope.clone(), state, result).unwrap();
            assert_eq!(recovered.state, state);
            assert!(recovered.envelope().unwrap() == &envelope);
            assert_eq!(
                recovered.sample_with(|_| panic!("recovery invoked the entropy source")),
                Err(TicketError::AlreadySampled)
            );
            assert_eq!(recovered.envelope().unwrap().binding(), envelope.binding());
        }
        assert!(matches!(
            Ticket::restore(original.intent, envelope, State::Proposed, None),
            Err(TicketError::Transition)
        ));
    }

    #[test]
    fn entropy_error_or_partial_fill_never_allows_a_second_attempt() {
        let mut ticket = proposal();
        assert_eq!(
            ticket.sample_with(|root| {
                root[0] = 1;
                Err(TicketError::Entropy)
            }),
            Err(TicketError::Entropy)
        );
        assert_eq!(ticket.sample_with(|_| panic!("second source call")), Err(TicketError::AlreadySampled));
        assert_eq!(ticket.committed(), Err(TicketError::Transition));
        assert!(matches!(ticket.envelope(), Err(TicketError::Uncommitted)));
    }

    #[test]
    fn source_unwind_and_zero_transaction_or_result_fail_closed() {
        let mut ticket = proposal();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = ticket.sample_with(|_| panic!("source interrupted"));
        }));
        assert!(panic.is_err());
        assert_eq!(ticket.sample_os(), Err(TicketError::AlreadySampled));
        let mut ticket = sampled();
        ticket.committed().unwrap();
        assert_eq!(ticket.submitted(Felt::ZERO), Err(TicketError::Transition));
        ticket.submitted(Felt::ONE).unwrap();
        assert_eq!(ticket.finish(State::Executed, Felt::ZERO), Err(TicketError::Transition));
        assert_eq!(ticket.finish(State::TerminalRejected, Felt::ZERO), Err(TicketError::Transition));
        ticket.finish(State::Executed, Felt::ONE).unwrap();
        assert_eq!(ticket.finish(State::TerminalRejected, Felt::ONE), Err(TicketError::Transition));
    }

    #[test]
    fn initialized_os_source_fills_a_complete_root() {
        let mut ticket = proposal();
        ticket.sample_os().unwrap();
        ticket.committed().unwrap();
        assert_eq!(ticket.envelope().unwrap().root.len(), 32);
        assert_eq!(ticket.sample_os(), Err(TicketError::AlreadySampled));
    }

    #[test]
    #[ignore = "requires getrandom denied by the syscall fault drill"]
    fn syscall_failure_has_no_fallback() {
        let mut ticket = proposal();
        assert_eq!(ticket.sample_os(), Err(TicketError::Entropy));
        assert_eq!(ticket.sample_os(), Err(TicketError::AlreadySampled));
        assert!(matches!(ticket.envelope(), Err(TicketError::Uncommitted)));
    }

    #[test]
    fn cross_language_context_boundaries() {
        let values: Vec<u64> = include_str!("../tests/fixtures/context-v1.txt")
            .lines()
            .map(|line| u64::from_str_radix(line.trim_start_matches("0x"), 16).unwrap())
            .collect();
        assert_eq!(values.len(), 1 + values[0] as usize * 9);
        for vector in values[1..].chunks_exact(9) {
            let mut ticket = proposal();
            ticket.context.timestamp = vector[0];
            ticket.intent.valid_from = vector[2];
            ticket.intent.valid_until = vector[3];
            ticket.context.order = vector[4];
            ticket.intent.last_order = vector[5];
            ticket.context.l2_gas = vector[6];
            assert_eq!(ticket.context.validate(&ticket.intent).is_ok(), vector[7] == 1);
            assert_eq!(timestamp_in_bounds(vector[0], vector[1]), vector[8] == 1);
        }
    }

    #[test]
    fn every_invalid_transition_is_rejected() {
        for state in [
            State::Proposed,
            State::Committed,
            State::Submitted,
            State::Executed,
            State::TerminalRejected,
            State::Consumed,
        ] {
            let mut ticket = sampled();
            ticket.state = state;
            if state != State::Proposed {
                assert_eq!(ticket.committed(), Err(TicketError::Transition));
            }
            if !matches!(state, State::Committed | State::Submitted) {
                assert_eq!(ticket.submitted(Felt::ONE), Err(TicketError::Transition));
            }
            for outcome in [State::Proposed, State::Committed, State::Submitted, State::Consumed] {
                assert_eq!(ticket.finish(outcome, Felt::ONE), Err(TicketError::Transition));
            }
            if matches!(state, State::Proposed | State::Committed | State::Consumed) {
                assert_eq!(ticket.finish(State::Executed, Felt::ONE), Err(TicketError::Transition));
                assert_eq!(ticket.finish(State::TerminalRejected, Felt::ONE), Err(TicketError::Transition));
            }
            if matches!(state, State::Proposed | State::Committed | State::Submitted) {
                assert_eq!(ticket.consume(), Err(TicketError::Transition));
            }
        }
    }
}
