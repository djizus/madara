use mc_sequencer_randomness::{
    journal::{Authorization, ChainProgress, Journal, JournalError, SCHEMA},
    protocol::{encode_bytes, Envelope, Intent},
    ticket::{Context, State},
};
use starknet_types_core::felt::Felt;
use tokio_postgres::{Client, NoTls};

const PRIMARY: &str = "host=127.0.0.1 port=55432 dbname=randomness user=randomness_writer_1 password=local-rehearsal";
const STANDBY: &str = "host=127.0.0.1 port=55433 dbname=randomness user=randomness_writer_1 password=local-rehearsal";
const ADMIN: &str = "host=127.0.0.1 port=55432 dbname=randomness user=postgres password=local-rehearsal";

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    client
}

fn intent() -> Intent {
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
        arguments: vec![Felt::ONE],
    }
}
fn context() -> Context {
    Context {
        order: 1,
        predecessor: Felt::ZERO,
        preceding_state: Felt::ZERO,
        timestamp: 1005,
        execution_config: Felt::ONE,
        l2_gas: 1_200_000_000,
    }
}
fn authorization() -> Authorization {
    let private_key = Felt::from(12345);
    let action = intent().identity().unwrap();
    let k = starknet_crypto::rfc6979_generate_k(&action, &private_key, None);
    let signature = starknet_crypto::sign(&private_key, &action, &k).unwrap();
    Authorization { public_key: starknet_crypto::get_public_key(&private_key), r: signature.r, s: signature.s }
}

#[tokio::test]
#[ignore = "requires the isolated madara-rand synchronous PostgreSQL pair; replaces only its rehearsal schema"]
async fn replicated_journal_rehearsal() {
    let admin = client(ADMIN).await;
    admin.query_one("SELECT pg_advisory_lock(4995003)", &[]).await.unwrap();
    admin.batch_execute("DROP SCHEMA IF EXISTS randomness CASCADE").await.unwrap();
    admin.batch_execute(SCHEMA).await.unwrap();
    let mut journal = Journal::connect(PRIMARY, STANDBY, 1).await.unwrap();
    assert!(journal.recover(&[]).await.unwrap().is_empty());
    let mut forged = authorization();
    forged.r = Felt::ONE;
    assert!(matches!(journal.accept(intent(), context(), forged).await, Err(JournalError::Signature)));
    assert!(journal.recover(&[]).await.unwrap().is_empty());
    let workers: Vec<_> = (0..16)
        .map(|_| {
            tokio::spawn(async {
                let mut contender = Journal::connect(PRIMARY, STANDBY, 1).await.unwrap();
                for _ in 0..1000 {
                    match contender.accept(intent(), context(), authorization()).await {
                        Ok(record) => return record,
                        Err(JournalError::UnresolvedProposal) => {
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await
                        }
                        Err(error) => panic!("concurrent admission failed: {error}"),
                    }
                }
                panic!("concurrent admission did not converge")
            })
        })
        .collect();
    let mut admitted = Vec::new();
    for worker in workers {
        admitted.push(worker.await.unwrap());
    }
    let record = admitted.pop().unwrap();
    assert!(admitted.iter().all(|other| other.envelope == record.envelope));
    let binding = record.envelope.binding().unwrap();
    let action = record.envelope.action;
    let mut later = context();
    later.timestamp = 5000;
    let duplicate = journal.accept(intent(), later, authorization()).await.unwrap();
    assert_eq!(duplicate.envelope.binding().unwrap(), binding);
    let mut changed = intent();
    changed.arguments.push(Felt::TWO);
    assert!(journal.accept(changed, context(), authorization()).await.is_err());
    eprintln!("PASS replicated acceptance, duplicate identity, conflicting nonce, fixed context");

    let writer = client(PRIMARY).await;
    assert!(writer.execute("UPDATE randomness.tickets SET envelope = NULL", &[]).await.is_err());
    let mut altered = record.envelope.clone();
    altered.root[0] ^= 1;
    assert!(writer
        .query_one(
            "SELECT randomness.accept($1,$2,$3,$4)",
            &[
                &1_i64,
                &action.to_bytes_be().to_vec(),
                &encode_bytes(&altered.encode().unwrap()),
                &altered.binding().unwrap().to_bytes_be().to_vec(),
            ]
        )
        .await
        .is_err());
    let stale = Journal::connect(PRIMARY, STANDBY, 2).await.unwrap();
    assert!(stale.record_submission(action, Felt::ONE, &[1]).await.is_err());
    assert!(stale.finish(action, Felt::ONE, Felt::ONE, false).await.is_err());
    assert!(stale.consume(action).await.is_err());
    eprintln!("PASS storage role denies direct writes, immutable root, stale epoch");

    let workers: Vec<_> = (0..16)
        .map(|_| {
            tokio::spawn(async {
                Journal::connect(PRIMARY, STANDBY, 1)
                    .await
                    .unwrap()
                    .accept(intent(), context(), authorization())
                    .await
                    .unwrap()
                    .envelope
                    .binding()
                    .unwrap()
            })
        })
        .collect();
    for worker in workers {
        assert_eq!(worker.await.unwrap(), binding);
    }
    journal.record_submission(action, Felt::ONE, &[1, 2, 3]).await.unwrap();
    journal.record_submission(action, Felt::TWO, &[4, 5, 6]).await.unwrap();
    journal.authorize_submission(&record.envelope, authorization(), Felt::ONE).await.unwrap();
    assert!(journal.authorize_submission(&record.envelope, authorization(), Felt::THREE).await.is_err());
    assert!(journal.authorize_submission(&altered, authorization(), Felt::ONE).await.is_err());
    let mut forged_auth = authorization();
    forged_auth.r = Felt::ONE;
    assert!(journal.authorize_submission(&record.envelope, forged_auth, Felt::ONE).await.is_err());
    eprintln!("PASS submission boundary binds registered transaction, root and authorization");
    assert!(journal.record_submission(action, Felt::ONE, &[9]).await.is_err());
    drop(journal);
    admin.batch_execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='randomness_writer_2') THEN CREATE ROLE randomness_writer_2 LOGIN PASSWORD 'local-rehearsal'; END IF; END $$;
        GRANT USAGE ON SCHEMA randomness TO randomness_writer_2;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA randomness TO randomness_writer_2;
        UPDATE randomness.stream SET epoch=2,writer='randomness_writer_2';").await.unwrap();
    assert!(writer
        .query_one("SELECT randomness.consume($1,$2)", &[&1_i64, &action.to_bytes_be().to_vec()])
        .await
        .is_err());
    let mut restarted =
        Journal::connect(&PRIMARY.replace("writer_1", "writer_2"), &STANDBY.replace("writer_1", "writer_2"), 2)
            .await
            .unwrap();
    assert_eq!(restarted.recover(&[]).await.unwrap()[0].envelope.binding().unwrap(), binding);
    eprintln!("PASS writer credential rotation preserves pending identity and fences the former role");
    let submissions = restarted.submissions().await.unwrap();
    assert_eq!(submissions.len(), 2);
    assert_eq!(submissions[0].bytes, vec![1, 2, 3]);
    assert_eq!(submissions[1].bytes, vec![4, 5, 6]);
    eprintln!("PASS concurrent duplicates and restart with two unresolved submission hashes");

    let chain = [ChainProgress { order: 1, binding, state: Felt::THREE, result: Felt::TWO }];
    assert_eq!(restarted.recover(&chain).await.unwrap()[0].result, None);
    restarted.finish(action, Felt::TWO, Felt::THREE, true).await.unwrap();
    restarted.finish(action, Felt::TWO, Felt::THREE, true).await.unwrap();
    assert!(restarted.finish(action, Felt::ONE, Felt::THREE, true).await.is_err());
    restarted.consume(action).await.unwrap();
    assert_eq!(restarted.recover(&chain).await.unwrap()[0].state, State::Consumed);
    assert!(restarted.recover(&[]).await.is_err());
    eprintln!("PASS chain-ahead reconciliation, terminal rejection, consumed nonce, conflicting result");

    admin
        .execute("UPDATE randomness.tickets SET envelope = set_byte(envelope,351,get_byte(envelope,351)#1)", &[])
        .await
        .unwrap();
    assert!(restarted.recover(&chain).await.is_err());
    admin.execute("DELETE FROM randomness.submissions", &[]).await.unwrap();
    admin.execute("DELETE FROM randomness.tickets", &[]).await.unwrap();
    assert!(restarted.recover(&[]).await.is_err());
    eprintln!("PASS corrupted entry and missing accepted suffix stop recovery");

    admin.batch_execute("DROP SCHEMA randomness CASCADE").await.unwrap();
    admin.batch_execute(SCHEMA).await.unwrap();
    let action = intent().identity().unwrap();
    let unsigned = intent();
    let nonce =
        encode_bytes(&[unsigned.chain, unsigned.deployment, unsigned.game, unsigned.actor, unsigned.nonce.into()]);
    let reserved = Envelope {
        action,
        order: 1,
        predecessor: Felt::ZERO,
        preceding_state: Felt::ZERO,
        timestamp: 1005,
        execution_config: Felt::ONE,
        l2_gas: 1_200_000_000,
        root: [0; 32],
    };
    writer
        .query_one(
            "SELECT randomness.reserve($1,$2,$3,$4,$5,$6,$7)",
            &[
                &1_i64,
                &nonce,
                &action.to_bytes_be().to_vec(),
                &1_i64,
                &encode_bytes(&unsigned.encode().unwrap()),
                &encode_bytes(&reserved.encode().unwrap()[..9]),
                &encode_bytes(&[Felt::ONE, Felt::TWO, Felt::THREE]),
            ],
        )
        .await
        .unwrap();
    let mut restarted = Journal::connect(PRIMARY, STANDBY, 1).await.unwrap();
    assert!(matches!(
        restarted.accept(intent(), context(), authorization()).await,
        Err(JournalError::UnresolvedProposal)
    ));
    assert!(matches!(restarted.recover(&[]).await, Err(JournalError::UnresolvedProposal)));
    eprintln!("PASS durable sampling reservation without a recoverable root never samples again");
    admin.batch_execute("DROP SCHEMA randomness CASCADE").await.unwrap();
    admin.batch_execute(SCHEMA).await.unwrap();
    let connection = client(PRIMARY).await;
    let paused = PausedStandby::new();
    let reservation = async {
        connection
            .query_one(
                "SELECT randomness.reserve($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &1_i64,
                    &nonce,
                    &action.to_bytes_be().to_vec(),
                    &1_i64,
                    &encode_bytes(&unsigned.encode().unwrap()),
                    &encode_bytes(&reserved.encode().unwrap()[..9]),
                    &encode_bytes(&[Felt::ONE, Felt::TWO, Felt::THREE]),
                ],
            )
            .await
    };
    assert!(tokio::time::timeout(std::time::Duration::from_millis(500), reservation).await.is_err());
    drop(paused);
    connection.simple_query("SELECT 1").await.unwrap();
    let mut restarted = Journal::connect(PRIMARY, STANDBY, 1).await.unwrap();
    assert!(matches!(
        restarted.accept(intent(), context(), authorization()).await,
        Err(JournalError::UnresolvedProposal)
    ));
    eprintln!("PASS standby loss prevents commit acknowledgement; ambiguous reservation never resamples");
}

struct PausedStandby;
impl PausedStandby {
    fn new() -> Self {
        assert!(std::process::Command::new("docker")
            .args(["pause", "madara-rand-journal-standby-1"])
            .status()
            .unwrap()
            .success());
        Self
    }
}
impl Drop for PausedStandby {
    fn drop(&mut self) {
        assert!(std::process::Command::new("docker")
            .args(["unpause", "madara-rand-journal-standby-1"])
            .status()
            .unwrap()
            .success());
    }
}
