package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gocql/gocql"
)

// ----------------------------------------------------------------------------
// Scylla session. gocql is the official Go driver; it speaks the
// native Cassandra protocol (v4/v5) that Scylla implements. The
// driver opens NumConns connections per host and routes queries
// through them using an internal stream multiplexer.
// ----------------------------------------------------------------------------

const (
	// scyllaConnectTimeout caps the dial time for each backend
	// host. Scylla's gossip can take a few seconds to converge
	// after a node restart, so we want a generous but bounded
	// timeout. 5 s is a good local default; cloud deployments
	// with cross-AZ hops usually bump this to 10 s.
	scyllaConnectTimeout = 5 * time.Second

	// scyllaNumConns is the per-host connection count. With
	// gocql's pipelining, two connections per host comfortably
	// saturate a single Scylla shard under the IceQ message
	// fan-out workload. Going higher helps only on hosts with
	// many cores / many shards.
	scyllaNumConns = 2

	// scyllaDefaultKeyspace is the keyspace IceQ uses by
	// default. The same value is hard-coded in
	// deploy/init/scylla-init.cql.
	scyllaDefaultKeyspace = "iceq"
)

// NewScyllaSession builds a *gocql.Session bound to the keyspace
// named in cfg.ScyllaKeyspace (or ICEQ_SCYLLA_KEYSPACE /
// "iceq" fallback). It returns the session on success, or an error
// wrapping whatever the connect step reported.
//
// Hosts are accepted as a comma-separated list of host:port pairs
// (e.g. "scylla:9042" or "node1:9042,node2:9042"). The driver will
// distribute connections across them automatically; with a single
// entry this is a no-op.
//
// Consistency is set to Quorum so writes survive a single-node
// failure once we move beyond the dev deployment with replication
// factor 1. With RF=1 the cluster treats the single replica as
// quorum, so the production transition is invisible at this layer.
func NewScyllaSession(cfg Config) (*gocql.Session, error) {
	hosts := cfg.ScyllaHosts
	if hosts == "" {
		hosts = envOr("ICEQ_SCYLLA_HOSTS", "scylla:9042")
	}
	keyspace := cfg.ScyllaKeyspace
	if keyspace == "" {
		keyspace = envOr("ICEQ_SCYLLA_KEYSPACE", scyllaDefaultKeyspace)
	}

	if hosts == "" {
		return nil, errors.New("db: ScyllaHosts is empty (set ICEQ_SCYLLA_HOSTS or Config.ScyllaHosts)")
	}
	if keyspace == "" {
		return nil, errors.New("db: ScyllaKeyspace is empty (set ICEQ_SCYLLA_KEYSPACE or Config.ScyllaKeyspace)")
	}

	cluster := gocql.NewCluster(splitCSV(hosts)...)
	// ConnectTimeout is per-host dial. We don't bound the
	// overall session creation time here — gocql dials hosts
	// in parallel, so the wait is roughly the slowest host.
	cluster.ConnectTimeout = scyllaConnectTimeout
	// Per-host connection count. The driver maintains
	// NumConns * len(hosts) total TCP sockets.
	cluster.NumConns = scyllaNumConns
	// Default consistency. CL=QUORUM requires N/2+1 replicas
	// to acknowledge; in the dev cluster with RF=1 this is
	// satisfied by the single node, and the setting
	// transparently scales to multi-DC production clusters.
	cluster.Consistency = gocql.Quorum
	// ReconnectIntervalPeriod is how often a disconnected
	// host is retried. We keep the driver default (1 s) but
	// make it explicit so a future tuning pass has the right
	// starting point.
	cluster.ReconnectInterval = time.Second
	// Keyspace is bound at session creation; the driver
	// injects it into every prepared statement.
	cluster.Keyspace = keyspace
	// Disable host discovery during the first few seconds of
	// startup. gocql otherwise tries to do a topology refresh
	// which races with the session's initial use; this flag
	// delays it until the first query triggers it.
	cluster.DisableInitialHostLookup = false

	// gocql.CreateSession dials every host, runs the keyspace
	// USE statement, and returns a session ready for queries.
	// On any host-level failure the call returns an error and
	// the partial session is closed internally.
	session, err := cluster.CreateSession()
	if err != nil {
		return nil, fmt.Errorf("db: create scylla session: %w", err)
	}
	return session, nil
}

// splitCSV splits a comma-separated string into a slice, trimming
// whitespace and dropping empty entries. Centralized so the three
// factories share the same parse semantics — especially important
// for hosts ("host1, host2, host3" with spaces) which gocql does
// NOT tolerate.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
