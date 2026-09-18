use starknet_types_core::felt::Felt;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

/// Only outstanding game submissions need pre-inclusion refusal attribution. Chain
/// receipts and the mempool remain authoritative for every included transaction.
#[derive(Clone)]
pub struct ExecutionObservers {
    pub account: Felt,
    waiting: Arc<Mutex<HashMap<Felt, watch::Sender<Option<String>>>>>,
}

impl ExecutionObservers {
    pub fn new(account: Felt) -> Self {
        Self { account, waiting: Default::default() }
    }

    pub fn watch(&self, transaction: Felt) -> RefusalWatch {
        let (sender, receiver) = watch::channel(None);
        self.waiting.lock().expect("execution observers poisoned").insert(transaction, sender);
        RefusalWatch { transaction, observers: self.clone(), receiver }
    }

    pub fn reporter(&self, transaction: Felt) -> Option<RefusalReporter> {
        self.waiting.lock().expect("execution observers poisoned").get(&transaction).cloned().map(RefusalReporter)
    }
}

#[derive(Debug)]
pub struct RefusalReporter(watch::Sender<Option<String>>);
impl RefusalReporter {
    pub fn report(self, reason: &str) {
        self.0.send_replace(Some(reason.to_owned()));
    }
}

pub struct RefusalWatch {
    transaction: Felt,
    observers: ExecutionObservers,
    pub receiver: watch::Receiver<Option<String>>,
}
impl Drop for RefusalWatch {
    fn drop(&mut self) {
        self.observers.waiting.lock().expect("execution observers poisoned").remove(&self.transaction);
    }
}
