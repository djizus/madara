use crate::service::Accepted;
use axum::http::StatusCode;
use starknet_core::types::Felt;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

type Decision = Option<Result<Accepted, StatusCode>>;
type Players = Arc<Mutex<HashMap<Felt, Pending>>>;

struct Pending {
    action: Felt,
    decision: watch::Sender<Decision>,
}

#[derive(Default, Clone)]
pub(crate) struct AdmissionSlots(Players);

pub(crate) enum Slot {
    New(Permit),
    Existing(watch::Receiver<Decision>),
}

pub(crate) struct Permit {
    players: Players,
    actor: Felt,
    decision: watch::Sender<Decision>,
}

impl AdmissionSlots {
    pub fn reserve(&self, actor: Felt, action: Felt) -> Result<Slot, StatusCode> {
        let mut players = self.0.lock().expect("admission slots poisoned");
        if let Some(pending) = players.get(&actor) {
            return if pending.action == action {
                Ok(Slot::Existing(pending.decision.subscribe()))
            } else {
                Err(StatusCode::CONFLICT)
            };
        }
        let (decision, _) = watch::channel(None);
        players.insert(actor, Pending { action, decision: decision.clone() });
        Ok(Slot::New(Permit { players: self.0.clone(), actor, decision }))
    }
}

impl Permit {
    pub fn subscribe(&self) -> watch::Receiver<Decision> {
        self.decision.subscribe()
    }
    pub fn resolve(&self, decision: Result<Accepted, StatusCode>) {
        self.decision.send_replace(Some(decision));
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.players.lock().expect("admission slots poisoned").remove(&self.actor);
    }
}

pub(crate) async fn decision(mut receiver: watch::Receiver<Decision>) -> Result<Accepted, StatusCode> {
    loop {
        if let Some(result) = receiver.borrow_and_update().clone() {
            return result;
        }
        receiver.changed().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
}

// A shared IP can host a full 96-player lobby. Two requests per action at four ticks
// per second fit this cap; actor slots prevent one player from occupying the queue.
pub(crate) struct IpLimits {
    window: Instant,
    requests: HashMap<IpAddr, u16>,
}
impl Default for IpLimits {
    fn default() -> Self {
        Self { window: Instant::now(), requests: HashMap::new() }
    }
}
impl IpLimits {
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.requests.clear();
            self.window = now;
        }
        if self.requests.len() >= 4096 && !self.requests.contains_key(&ip) {
            return false;
        }
        let count = self.requests.entry(ip).or_default();
        if *count >= 1024 {
            return false;
        }
        *count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_flooding_player_uses_one_slot_and_duplicates_follow_the_same_admission() {
        let slots = AdmissionSlots::default();
        let Slot::New(first) = slots.reserve(Felt::ONE, Felt::from(10)).unwrap() else { panic!("new actor") };
        for _ in 0..1000 {
            assert!(matches!(slots.reserve(Felt::ONE, Felt::from(11)), Err(StatusCode::CONFLICT)));
        }
        let Slot::Existing(duplicate) = slots.reserve(Felt::ONE, Felt::from(10)).unwrap() else { panic!("duplicate") };
        let Slot::New(other) = slots.reserve(Felt::TWO, Felt::from(12)).unwrap() else {
            panic!("other player blocked")
        };
        first.resolve(Ok(Accepted { action: Felt::from(10), order: 1 }));
        assert_eq!(decision(duplicate).await.unwrap().order, 1);
        assert!(matches!(slots.reserve(Felt::ONE, Felt::from(11)), Err(StatusCode::CONFLICT)));
        drop(first);
        assert!(matches!(slots.reserve(Felt::ONE, Felt::from(11)), Ok(Slot::New(_))));
        drop(other);
    }

    #[tokio::test]
    async fn a_failed_queue_send_releases_the_actor_and_wakes_duplicate_waiters() {
        let slots = AdmissionSlots::default();
        let Slot::New(permit) = slots.reserve(Felt::ONE, Felt::TWO).unwrap() else { panic!("new actor") };
        let waiting = permit.subscribe();
        drop(permit);
        assert!(matches!(decision(waiting).await, Err(StatusCode::SERVICE_UNAVAILABLE)));
        assert!(matches!(slots.reserve(Felt::ONE, Felt::from(3)), Ok(Slot::New(_))));
    }

    #[test]
    fn ip_limits_bound_abuse_without_sharing_a_budget_between_addresses() {
        let mut limits = IpLimits::default();
        let now = limits.window;
        let first = "127.0.0.1".parse().unwrap();
        for _ in 0..1024 {
            assert!(limits.allow(first, now));
        }
        assert!(!limits.allow(first, now));
        assert!(limits.allow("127.0.0.2".parse().unwrap(), now));
        assert!(limits.allow(first, now + Duration::from_secs(1)));
    }
}
