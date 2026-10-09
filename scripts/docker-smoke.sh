#!/bin/sh
# End-to-end check of the Docker image with the session sandbox required:
# builds the image, runs it, starts a real tmate 2.4.0 host (the static
# Linux binary action-tmate uses) in a second container, joins as a viewer
# over plain ssh from a third, and checks that the viewer sees the host's
# screen while the server log shows the session worker sandboxed.
#
# Usage: scripts/docker-smoke.sh
# Env:   SMOKE_IMAGE          image tag to build/run (default tmate-server-rs)
#        SMOKE_SKIP_BUILD=1   use the existing image
#        SMOKE_SECURITY_OPT   docker --security-opt for the server
#                             (default: seccomp=<repo>/docker/seccomp.json,
#                             the profile that lets an unprivileged process
#                             create namespaces; see README.md, Sandboxing)
#        SMOKE_SERVER_ARGS    extra server flags (default: --sandbox require)
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${SMOKE_IMAGE:-tmate-server-rs}
SECOPT=${SMOKE_SECURITY_OPT:-seccomp=$here/docker/seccomp.json}
SERVER_ARGS=${SMOKE_SERVER_ARGS:---sandbox require}
id=$$
NET=tmate-smoke-$id
SRV=tmate-smoke-srv-$id
HOST=tmate-smoke-host-$id
CLIENT_VOL=tmate-smoke-client   # caches the downloaded tmate binary
ALPINE=alpine:3.21

case "$(docker version --format '{{.Server.Arch}}')" in
  arm64) TMATE_ARCH=arm64v8 ;;
  amd64) TMATE_ARCH=amd64 ;;
  *) echo "unsupported docker architecture"; exit 2 ;;
esac
TMATE_URL="https://github.com/tmate-io/tmate/releases/download/2.4.0/tmate-2.4.0-static-linux-$TMATE_ARCH.tar.xz"

cleanup() {
  docker rm -f "$SRV" "$HOST" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL: $*" >&2; echo "--- server log" >&2; docker logs "$SRV" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' >&2 || true; exit 1; }

if [ "${SMOKE_SKIP_BUILD:-0}" != 1 ]; then
  echo "building $IMAGE"
  docker build -q -t "$IMAGE" "$here" >/dev/null
fi

docker network create "$NET" >/dev/null

echo "starting the server with --security-opt $SECOPT and: $SERVER_ARGS"
# shellcheck disable=SC2086
docker run -d --name "$SRV" --network "$NET" --security-opt "$SECOPT" \
  -e SSH_HOSTNAME="$SRV" -e RUST_LOG=info "$IMAGE" $SERVER_ARGS >/dev/null
i=0
until docker logs "$SRV" 2>&1 | grep -q "accepting connections"; do
  i=$((i + 1)); [ $i -lt 60 ] || fail "server did not start"
  if [ "$(docker inspect -f '{{.State.Running}}' "$SRV")" != true ]; then fail "server exited"; fi
  sleep 0.5
done
FP=$(docker logs "$SRV" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -o 'SHA256:[A-Za-z0-9+/]*' | head -1)
[ -n "$FP" ] || fail "no fingerprint in the server log"
docker logs "$SRV" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -q "sandbox: each session runs in a locked-down worker process" \
  || fail "the server did not report a working sandbox"
echo "server up, fingerprint $FP, sandbox probe passed"

docker volume create "$CLIENT_VOL" >/dev/null
docker run --rm -v "$CLIENT_VOL:/client" "$ALPINE" sh -ec "
  cd /client
  if [ ! -x tmate-$TMATE_ARCH ]; then
    wget -q '$TMATE_URL' -O t.tar.xz
    tar -xJf t.tar.xz
    mv tmate-2.4.0-static-linux-$TMATE_ARCH/tmate tmate-$TMATE_ARCH
    rm -rf t.tar.xz tmate-2.4.0-static-linux-$TMATE_ARCH
  fi" || fail "cannot fetch the tmate client"

echo "starting a tmate 2.4.0 host"
docker run -d --name "$HOST" --network "$NET" -v "$CLIENT_VOL:/client:ro" "$ALPINE" sleep 300 >/dev/null
host() { docker exec -e TERM=xterm "$HOST" /client/tmate-$TMATE_ARCH -S /tmp/t.sock -f /tmp/tmate.conf "$@"; }
docker exec "$HOST" sh -c "printf 'set -g tmate-server-host $SRV\nset -g tmate-server-port 2200\nset -g tmate-server-ed25519-fingerprint \"$FP\"\n' > /tmp/tmate.conf"
host new-session -d -x 80 -y 24
docker exec "$HOST" timeout 30 /client/tmate-$TMATE_ARCH -S /tmp/t.sock wait tmate-ready || fail "wait tmate-ready did not return"
SSH=$(host display -p '#{tmate_ssh}')
TOKEN=${SSH##* }; TOKEN=${TOKEN%@*}
echo "host ready: $SSH"
# Leave tmate's tips screen (copy mode) and put something on the pane.
i=0; until [ "$(host display -p '#{pane_in_mode}')" = 1 ]; do i=$((i + 1)); [ $i -lt 40 ] || break; sleep 0.25; done
host send-keys q
i=0; until [ "$(host display -p '#{pane_in_mode}')" = 0 ]; do i=$((i + 1)); [ $i -lt 40 ] || break; sleep 0.25; done
MARK="smoke-$id-ok"
host send-keys "clear; echo $MARK" Enter
sleep 1

echo "joining as a viewer over ssh"
SCREEN=$(docker run --rm --network "$NET" "$ALPINE" sh -c "
  apk add -q --no-cache openssh-client >/dev/null 2>&1
  sleep 4 | timeout 10 ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -p 2200 '$TOKEN@$SRV' 2>/dev/null | cat" | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' | tr -d '\r' || true)
echo "$SCREEN" | grep -q "$MARK" || { echo "$SCREEN" | tail -5 >&2; fail "the viewer did not see the host's screen ($MARK)"; }
echo "$SCREEN" | grep -q '0:' || fail "no status line on the viewer's screen"
echo "viewer saw the host's screen and the status line"

LOG=$(docker logs "$SRV" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo "$LOG" | grep -q "session worker sandboxed" || fail "no 'session worker sandboxed' line in the server log"
echo "$LOG" | grep -q "A mate has joined" || true
echo "--- server log, sandbox and session lines:"
echo "$LOG" | grep -E "sandbox|session ready|viewer attached|viewer left" | cut -c1-240
echo
echo "OK: tmate 2.4.0 host + ssh viewer worked through a sandboxed session worker"
