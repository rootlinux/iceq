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
4. Require `/health` to report both `nats: ok` and
   `jetstream_delivery: ok` before enabling the gateway.

## Recovery behavior

- The message row and opaque outbox row share a logged batch. A failed store
  returns no persisted ACK; replay resumes with the same deterministic ID.
- The recovery worker scans 16 bounded outbox buckets and retries no more than
  100 pending direct/group deliveries per pass.
- JetStream publishes carry the deterministic message ID as `Nats-Msg-Id` and
  wait for PubAck. Only then is the Scylla receipt marked delivered and its
  outbox row removed.
- Do not delete pending outbox rows manually. Restore Scylla/NATS health and
  allow the worker to retry them.

## Exactly-once boundary

Scylla and JetStream do not share a transaction. A process can crash after
JetStream PubAck but before the delivered-state CAS. Re-publishing within the
configured 24-hour JetStream duplicate window is suppressed. Recovery delayed
beyond that window may create a second physical bus publish, so gateways and
clients must retain stable message-ID deduplication. The deterministic Scylla
primary key still prevents a second logical message row. This is a logical
no-second-store/no-second-visible-delivery contract, not a physical Core NATS
exactly-once claim.

Disappearing messages apply their TTL to receipt, row, indexes, and outbox.
Explicit `off` receipts and outbox rows are durable without an arbitrary TTL.
