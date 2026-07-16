#!/bin/sh
# Print the locally generated IceQ .onion address once the Tor hidden-service
# keypair and hostname file exist.
#
# The Tor container writes the locally generated v3 onion address to its
# hostname file. This script polls that local file (via `docker exec`) for up
# to 60s and prints the address as soon as it appears. A hostname file does
# not prove Tor consensus publication or external onion reachability.
#
# Usage:
#   ./deploy/scripts/onion-address.sh
#
# Exit codes:
#   0 — address found and printed
#   1 — timed out waiting for the address (container still booting or
#       not running; check `docker compose --profile tor logs tor`)

set -eu

CONTAINER="iceq-tor"
MAX_ATTEMPTS=30
SLEEP_SECONDS=2

# Sanity check: is docker available?
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed or not on PATH" >&2
    exit 1
fi

# Sanity check: is the container running?
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "Error: container '$CONTAINER' is not running." >&2
    echo "Start the stack first: docker compose -f deploy/docker-compose.yml --profile tor up -d" >&2
    exit 1
fi

echo "Waiting for .onion address (up to $((MAX_ATTEMPTS * SLEEP_SECONDS))s)..."
i=0
while [ "$i" -lt "$MAX_ATTEMPTS" ]; do
    # goldy/tor-hidden-service nests each hostname file under a per-service
    # directory (for example /var/lib/tor/hidden_service/icecq/hostname).
    ADDR=$(
        docker exec "$CONTAINER" sh -lc '
            for f in /var/lib/tor/hidden_service/*/hostname; do
                if [ -f "$f" ]; then
                    cat "$f"
                    exit 0
                fi
            done
            exit 1
        ' 2>/dev/null || true
    )
    if [ -n "$ADDR" ]; then
        echo ""
        echo "✓ IceQ .onion address:"
        echo ""
        echo "  http://$ADDR"
        echo ""
        echo "Add this line to deploy/.env.local to enable Onion-Location:"
        echo "  ICEQ_ONION_LOCATION=http://$ADDR"
        echo ""
        echo "Share this address. It never changes as long as the"
        echo "tor_keys Docker volume exists."
        echo ""
        echo "Test it with:"
        echo "  torify curl -s http://$ADDR/health"
        exit 0
    fi
    i=$((i + 1))
    sleep "$SLEEP_SECONDS"
done

echo ""
echo "Timeout: Tor container did not create a local hostname file within" >&2
echo "$((MAX_ATTEMPTS * SLEEP_SECONDS))s. Diagnose with:" >&2
echo "  docker compose -f deploy/docker-compose.yml --profile tor logs tor" >&2
exit 1
