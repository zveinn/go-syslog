#!/usr/bin/env bash
# End-to-end check: send via UDP+TCP to the syslog-test container, then read
# /var/log/received.log inside the container and assert it contains each
# expected message exactly. Run from the repo root.
set -euo pipefail

CONTAINER="${SYSLOG_CONTAINER:-syslog-test}"

if ! podman ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "container $CONTAINER is not running" >&2
    exit 1
fi

# Truncate the log so we only inspect this run.
podman exec "$CONTAINER" sh -c '>/var/log/received.log'

go run ./example/send/ >/dev/null

# rsyslog buffers a tick; give it a moment to flush.
sleep 1

LOG=$(podman exec "$CONTAINER" cat /var/log/received.log)

expect() {
    local label="$1" needle="$2"
    if grep -Fq -- "$needle" <<<"$LOG"; then
        printf '  OK  %s\n' "$label"
    else
        printf 'FAIL  %s — missing: %s\n' "$label" "$needle" >&2
        exit 1
    fi
}

expect "RFC 3164 / UDP" \
  '[imudp] <165>May 19 10:30:00 demo-host demoapp[1234]: RFC3164-UDP hello from go-syslog'

expect "RFC 5424 / UDP (with escaped SD-VALUE)" \
  '[imudp] <166>1 2026-05-19T10:30:00.123Z demo-host.example.com demoapp 1234 DEMO01 [demo@32473 transport="udp" note="quotes \" and \] need escaping"] RFC5424-UDP hello from go-syslog'

expect "RFC 5424 + RFC 6587 / TCP frame 1" \
  '[imtcp] <166>1 2026-05-19T10:30:00.123Z demo-host.example.com demoapp 1234 BATCH01 - RFC5424-TCP first message'

expect "RFC 5424 + RFC 6587 / TCP frame 2" \
  '[imtcp] <166>1 2026-05-19T10:30:01.123Z demo-host.example.com demoapp 1234 BATCH02 - RFC5424-TCP second message'

expect "RFC 5424 + RFC 6587 / TCP frame 3" \
  '[imtcp] <166>1 2026-05-19T10:30:02.123Z demo-host.example.com demoapp 1234 BATCH03 - RFC5424-TCP third message'

echo
echo "all 5 messages received and verified."
