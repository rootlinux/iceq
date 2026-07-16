# Durable message delivery runbook

IceQ treats message-service, not ws-gateway or Redis, as the authority for a
`persisted` acknowledgement. Operators must apply Scylla migration 012 and
keep JetStream file storage healthy before accepting message traffic.

## Rollout gate

1. Apply `012_durable_message_ingest.cql` using the existing-volume command in
   the README and verify `message_ingest`, `message_outbox`, and
   `group_message_outbox` exist.
2. Start NATS with `--jetstream` and a persistent `/data` volume.
3. Start message-service. Startup fails closed unless the `ICEQ_DELIVERY`
   stream can be created or reconciled.
4. Require message-service `/health` to report `jetstream_delivery: ok` and
   ws-gateway `/health` to report `jetstream_consumer: ok` before enabling
   traffic.

## Recovery behavior

- The message row and opaque outbox row share a logged batch. A failed store
  returns no persisted ACK; replay resumes with the same deterministic ID.
- The recovery worker scans 16 bounded outbox buckets and retries no more than
  100 pending direct/group deliveries per pass.
- JetStream publishes carry the deterministic message ID as `Nats-Msg-Id` and
  wait for PubAck, but PubAck never removes the Scylla outbox.
- The durable `ICEQ_GATEWAY_DELIVERY` consumer atomically writes a scoped seen
  marker and the envelope to `poll:stream:<uin>`. It then requests a
  `delivery.accepted` receipt from message-service. Only that receipt marks the
  Scylla record delivered and deletes the outbox; JetStream is explicitly
  acknowledged last.
- Do not delete pending outbox rows manually. Restore Scylla/NATS health and
  allow the worker to retry them.

## Exactly-once boundary

Scylla, JetStream, and Redis do not share a transaction. Their ordering is
deliberately retry-safe: a crash before Redis acceptance leaves JetStream
unacked; a crash after Redis acceptance replays into the scoped seen-marker
no-op; a crash after the message-service receipt repeats an idempotent delivered
CAS. The producer's 24-hour duplicate window reduces physical bus repeats, but
recipient correctness does not depend on that window. The persistent recipient
queue and stable message ID prevent a second visible queue item. This is a
logical no-second-store/no-second-visible-delivery contract, not a claim that
every underlying bus operation executes physically once.

Disappearing messages apply their TTL to receipt, row, indexes, and outbox.
Explicit `off` receipts and outbox rows are durable without an arbitrary TTL.
The recovery worker continually refreshes broker availability for pending
outbox rows, while accepted `off` messages make the recipient Redis stream
persistent. Expiring acceptance markers use the message's remaining TTL and
never shorten a stream that contains longer-lived or retention-off entries.
