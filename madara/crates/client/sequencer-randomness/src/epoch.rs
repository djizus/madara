use crate::protocol::root_limbs;
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const EPOCH_TAG: Felt = Felt::from_hex_unchecked("0x455445524e554d5f45504f4348");

/// Only this secret survives restart. Tickets, assigned orders and roots do not.
#[derive(Serialize, Deserialize)]
pub(crate) struct EpochSecret {
    pub first_order: u64,
    pub last_order: u64,
    secret: [u8; 32],
}

impl EpochSecret {
    pub fn create(first_order: u64, last_order: u64) -> anyhow::Result<Self> {
        ensure!(first_order > 0 && last_order >= first_order, "invalid epoch range");
        let mut secret = [0; 32];
        let filled = rustix::rand::getrandom(&mut secret, rustix::rand::GetRandomFlags::empty())?;
        ensure!(filled == secret.len(), "incomplete epoch entropy");
        Ok(Self { first_order, last_order, secret })
    }

    pub fn commitment(&self) -> Felt {
        let (low, high) = root_limbs(self.secret);
        Poseidon::hash_array(&[EPOCH_TAG, Felt::ONE, low.into(), high.into()])
    }

    pub fn root(&self, order: u64) -> anyhow::Result<[u8; 32]> {
        ensure!((self.first_order..=self.last_order).contains(&order), "order outside epoch");
        let (low, high) = root_limbs(self.secret);
        Ok(Poseidon::hash_array(&[low.into(), high.into(), order.into()]).to_bytes_be())
    }

    pub fn reveal(&self) -> [Felt; 2] {
        let (low, high) = root_limbs(self.secret);
        [low.into(), high.into()]
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        serde_json::from_slice(&std::fs::read(path).context("read randomness epoch secret")?)
            .context("decode randomness epoch secret")
    }

    /// Persist before publishing the commitment. Rename plus directory sync covers either
    /// side of a crash without retaining any per-ticket data or a second transaction log.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let parent = path.parent().context("epoch secret path needs a parent")?;
        std::fs::create_dir_all(parent)?;
        let temporary = path.with_extension("pending");
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_secret_reconstructs_every_root_and_bounds_the_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("epoch.json");
        let epoch = EpochSecret::create(7, 10).unwrap();
        epoch.save(&path).unwrap();
        let restored = EpochSecret::load(&path).unwrap();
        assert_eq!(epoch.commitment(), restored.commitment());
        assert_eq!(epoch.reveal(), restored.reveal());
        for order in 7..=10 {
            assert_eq!(epoch.root(order).unwrap(), restored.root(order).unwrap());
        }
        assert!(epoch.root(6).is_err());
        assert!(epoch.root(11).is_err());
        let next = EpochSecret::create(11, 20).unwrap();
        next.save(&path).unwrap();
        assert_eq!(EpochSecret::load(&path).unwrap().commitment(), next.commitment());
        assert_ne!(next.commitment(), epoch.commitment());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
