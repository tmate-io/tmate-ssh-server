#!/bin/sh
# Runs the parity suite: the old C server (built from its own Dockerfile) as
# the reference, the Rust server under test, the same tmate 2.4.0 client and
# scripted viewers against both.
#
# Usage: scripts/parity.sh [path-to-old-tmate-ssh-server-checkout]
# Needs docker and a `tmate` binary in PATH.
set -eu

# The reference is the last commit of the C server. After the rewrite was
# merged it is no longer a sibling checkout, so fall back to a worktree of
# that commit inside target/.
OLD_COMMIT=d7334ee4c3c8036c27fb35c7a24df3a88a15676b
if [ $# -gt 0 ] && [ -d "$1" ]; then
  OLD_SRC=$1; shift
elif [ -d "$(dirname "$0")/../../tmate-ssh-server/compat" ]; then
  OLD_SRC=$(dirname "$0")/../../tmate-ssh-server
else
  OLD_SRC=$(dirname "$0")/../target/old-server
  if [ ! -d "$OLD_SRC" ]; then
    echo "checking out the old C server ($OLD_COMMIT) into $OLD_SRC"
    git -C "$(dirname "$0")/.." worktree add --detach "target/old-server" "$OLD_COMMIT"
  fi
fi
PORT=${TMATE_REF_PORT:-2201}
KEYS=${TMPDIR:-/tmp}/tmate-parity-keys
IMAGE=tmate-ssh-server-old
NAME=tmate-parity-ref

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building reference image from $OLD_SRC"
  docker build -t "$IMAGE" "$OLD_SRC"
fi

mkdir -p "$KEYS"
[ -f "$KEYS/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEYS/ssh_host_ed25519_key"
[ -f "$KEYS/ssh_host_rsa_key" ] || ssh-keygen -q -t rsa -b 2048 -N "" -f "$KEYS/ssh_host_rsa_key"

docker rm -f "$NAME" >/dev/null 2>&1 || true
# --privileged: the old server chroots and unshares namespaces per session.
docker run -d --name "$NAME" --privileged -p "$PORT:2200" \
  -e SSH_KEYS_PATH=/keys -e SSH_HOSTNAME=127.0.0.1 -e "SSH_PORT_ADVERTISE=$PORT" \
  -v "$KEYS:/keys" "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT

for _ in $(seq 1 50); do
  nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
  sleep 0.2
done

TMATE_REF_ADDR="127.0.0.1:$PORT" \
TMATE_REF_FINGERPRINT=$(ssh-keygen -lf "$KEYS/ssh_host_ed25519_key.pub" -E sha256 | awk '{print $2}') \
  cargo test --test parity --test replay -- --test-threads=1 "$@"
