#!/usr/bin/env bash
# Spin up an rsyslog container, run a comprehensive syslog load against it
# (RFC 3164 + RFC 5424 × UDP + TCP × octet-counted + non-transparent framing,
# plus boundary corner cases), then verify every expected message is present
# in the container's received log. Always cleans up the container.
set -euo pipefail

CONTAINER="${SYSLOG_CONTAINER:-go-syslog-tests}"
IMAGE="${SYSLOG_IMAGE:-docker.io/alpine:latest}"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TMPDIR="$(mktemp -d)"

cleanup() {
    local rc=$?
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR"
    exit "$rc"
}
trap cleanup EXIT INT TERM

podman rm -f "$CONTAINER" >/dev/null 2>&1 || true

echo "==> Pulling $IMAGE"
podman pull "$IMAGE" >/dev/null

echo "==> Starting rsyslog container ($CONTAINER)"
podman run -d --name "$CONTAINER" \
    -p 5514:514/udp -p 5514:514/tcp \
    -v "$HERE/server/rsyslog.conf:/etc/rsyslog.conf:Z,ro" \
    --entrypoint sh \
    "$IMAGE" \
    -c 'apk add --no-cache rsyslog >/dev/null && touch /var/log/received.log && rsyslogd -n -f /etc/rsyslog.conf' \
    >/dev/null

echo "==> Waiting for rsyslog to bind ports"
ready=0
for _ in $(seq 1 60); do
    if podman exec "$CONTAINER" sh -c \
        '(ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null) | grep -q ":514"' 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.3
done
if [ "$ready" -ne 1 ]; then
    echo "rsyslog did not bind within timeout" >&2
    podman logs "$CONTAINER" >&2 || true
    exit 1
fi
sleep 1 # let accept loops settle

PROFDIR="$HERE/profiles"
mkdir -p "$PROFDIR"

echo "==> Generating load (6 categories × ~8k each + corner cases)"
START=$(date +%s)
(cd "$ROOT" && go run ./container_tests/load \
    -expect "$TMPDIR/expected.txt" \
    -cpuprofile "$PROFDIR/cpu.pprof" \
    -memprofile "$PROFDIR/mem.pprof")
ELAPSED=$(( $(date +%s) - START ))
echo "    (send phase took ${ELAPSED}s)"
echo "    profiles: $PROFDIR/{cpu,mem}.pprof"

echo "==> Waiting for rsyslog to flush"
# Poll until the received-log line count stabilises, then take one extra
# breath. This adapts to load size without a fixed long sleep.
prev=0
stable=0
for _ in $(seq 1 60); do
    cur=$(podman exec "$CONTAINER" sh -c 'wc -l < /var/log/received.log' 2>/dev/null | tr -d ' ' || echo 0)
    if [ "$cur" = "$prev" ] && [ "$cur" -gt 0 ]; then
        stable=$((stable + 1))
        if [ "$stable" -ge 2 ]; then break; fi
    else
        stable=0
    fi
    prev="$cur"
    sleep 0.5
done
sleep 1

echo "==> Fetching received log"
podman exec "$CONTAINER" cat /var/log/received.log > "$TMPDIR/received.raw"

# Drop rsyslog's internal startup chatter.
grep -E '^\[im(udp|tcp)\] ' "$TMPDIR/received.raw" > "$TMPDIR/received.txt" || true

expected_n=$(wc -l < "$TMPDIR/expected.txt" | tr -d ' ')
received_n=$(wc -l < "$TMPDIR/received.txt" | tr -d ' ')

echo
printf "    expected: %d\n" "$expected_n"
printf "    received: %d\n" "$received_n"

# Byte-wise sort + comm so UTF-8 in message bodies doesn't get re-ordered
# differently by sort vs comm.
export LC_ALL=C
sort "$TMPDIR/expected.txt" > "$TMPDIR/expected.sorted"
sort "$TMPDIR/received.txt" > "$TMPDIR/received.sorted"

comm -23 "$TMPDIR/expected.sorted" "$TMPDIR/received.sorted" > "$TMPDIR/missing"
comm -13 "$TMPDIR/expected.sorted" "$TMPDIR/received.sorted" > "$TMPDIR/extra"

missing_n=$(wc -l < "$TMPDIR/missing" | tr -d ' ')
extra_n=$(wc -l < "$TMPDIR/extra" | tr -d ' ')

# Per-category receive counts. RFC is detected by looking at the byte after
# PRI: RFC 5424 messages start "<PRI>1 ", RFC 3164 messages start with a
# three-letter month abbreviation. Transport is taken from the inputname
# tag rsyslog stamped on each line. Both 6587 framings produce identical
# de-framed messages so they can't be separated on this side — the actual
# framing distinction is enforced upstream by the load generator's choice
# of FrameRFC6587 vs FrameRFC6587NonTransparent (the byte-exact diff below
# would have failed if either framing produced wrong wire bytes).
count() { grep -Ec "$1" "$TMPDIR/received.txt" || true; }

c_3164_udp=$(count '^\[imudp\] <[0-9]+>[A-Z][a-z][a-z] ')
c_5424_udp=$(count '^\[imudp\] <[0-9]+>1 ')
c_3164_tcp=$(count '^\[imtcp\] <[0-9]+>[A-Z][a-z][a-z] ')
c_5424_tcp=$(count '^\[imtcp\] <[0-9]+>1 ')

echo
echo "    by category (received):"
printf "      RFC 3164 / UDP : %6d\n" "$c_3164_udp"
printf "      RFC 5424 / UDP : %6d\n" "$c_5424_udp"
printf "      RFC 3164 / TCP : %6d  (octet-counting + non-transparent)\n" "$c_3164_tcp"
printf "      RFC 5424 / TCP : %6d  (octet-counting + non-transparent)\n" "$c_5424_tcp"
echo

fail=0
if [ "$missing_n" -gt 0 ]; then
    echo "    MISSING ($missing_n):"
    head -5 "$TMPDIR/missing" | sed 's/^/      /'
    [ "$missing_n" -gt 5 ] && echo "      ... and $((missing_n - 5)) more"
    fail=1
fi
if [ "$extra_n" -gt 0 ]; then
    echo "    UNEXPECTED ($extra_n):"
    head -5 "$TMPDIR/extra" | sed 's/^/      /'
    [ "$extra_n" -gt 5 ] && echo "      ... and $((extra_n - 5)) more"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "    PASS: every message round-tripped byte-for-byte."
    exit 0
else
    echo "    FAIL"
    exit 1
fi
