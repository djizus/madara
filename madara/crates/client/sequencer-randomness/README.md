# Recorded sequencer randomness

The crate implements version 1 codecs, checked full-width OS sampling and the accepted-ticket state machine.
`Tickets` serializes live admission by canonical actor nonce; duplicate transport requests reuse the same ticket.
The working set alone is not durable. Before sampling, the journal must persist exclusive ownership of the proposal;
only its replicated commit acknowledgement may call `committed`. A lost sampling attempt cannot be recreated.

Accepted contexts have no maximum age; a future timestamp is rejected. Signed expiry applies at acceptance.
Execution lag above 300 seconds emits an operational warning and never cancels the ticket. The leader also checks
the current admission time against signed expiry, so an old closed block cannot admit an expired intent.
The same boundary vectors run in Rust and Cairo from `tests/fixtures/context-v1.txt`. Credentials, request identifiers
and transaction hashes never enter action identity. Pending actions retain their accepted authorization evidence.

The protocol is specified in the companion Eternum repository at
`docs/architecture/sequencer-randomness-protocol.md`. `tests/fixtures/v1.txt` is byte-identical to its Cairo fixture.
Five fixed roots exercise zero, all bits set, asymmetric byte order, the top bit and the low bit. Each includes
canonical intent/envelope felts and bytes, action/binding hashes and three draws from the unchanged game derivation.
These are test vectors, never production entropy.

Run `cargo test -p mc-sequencer-randomness --locked` and
`cargo clippy -p mc-sequencer-randomness --all-targets --all-features --locked -- -D warnings` from the repository root.
The companion `contracts/l3/randomness-protocol/check.py` runs both languages plus the unchanged game function and
writes logs and a machine-readable report with source hashes.

Operator honesty is trusted. Passing codec tests establishes neither honest sampling nor durability, fencing,
preview resistance or performance of the accepted-ticket protocol.

The PostgreSQL journal client uses the schema in `src/journal.sql`. It reserves sampling ownership with synchronous
replication before calling the OS, verifies accepted records on the hot standby, and restores lifecycle state without
creating a sampler. Storage functions fence each writer by login role and authority epoch. The companion
`deploy/madara-rand/README.md` records acknowledgement, promotion and recovery procedures.

Run the actual two-volume rehearsal with `deploy/madara-rand/journal/check.py` in the Eternum checkout. It requires
the isolated Compose project and replaces its rehearsal schema. The host-loss gate remains separate.
