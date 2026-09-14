# Recorded sequencer randomness

The first increment defines version 1 action and entropy-envelope codecs. It does not yet sample entropy, admit
actions, connect a journal or modify the batcher. The absence of those consumers is an explicit integration gate.

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
