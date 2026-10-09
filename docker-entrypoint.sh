#!/bin/sh
# Same environment variables as the old tmate-ssh-server image, so existing
# deployments can swap the image without changing their configuration.
set -e

SSH_PORT_LISTEN=${SSH_PORT_LISTEN:-2200}
SSH_PORT_ADVERTIZE=${SSH_PORT_ADVERTIZE:-${SSH_PORT_LISTEN}}
SSH_PORT_ADVERTISE=${SSH_PORT_ADVERTISE:-${SSH_PORT_ADVERTIZE}}
SSH_KEYS_PATH=${SSH_KEYS_PATH:-/keys}

# Platforms without persistent volumes (Fly secrets, Kubernetes secrets as
# env) hand the host key over as an environment variable. Every region must
# serve the same key, because clients pin one fingerprint per key type.
if [ -n "${SSH_HOST_ED25519_KEY:-}" ]; then
  umask 077
  printf '%s\n' "${SSH_HOST_ED25519_KEY}" > "${SSH_KEYS_PATH}/ssh_host_ed25519_key"
fi
if [ -n "${SSH_HOST_RSA_KEY:-}" ]; then
  umask 077
  printf '%s\n' "${SSH_HOST_RSA_KEY}" > "${SSH_KEYS_PATH}/ssh_host_rsa_key"
fi

set -- --listen "0.0.0.0:${SSH_PORT_LISTEN}" --advertised-port "${SSH_PORT_ADVERTISE}" --keys-dir "${SSH_KEYS_PATH}" "$@"

if [ -n "${SSH_HOSTNAME}" ]; then
  set -- --host "${SSH_HOSTNAME}" "$@"
fi

if [ "${USE_PROXY_PROTOCOL:-0}" -eq "1" ]; then
  set -- --proxy-protocol "$@"
fi

# The tmate-websocket backend, as the old image selected it: HAS_WEBSOCKET=1
# means it runs alongside on localhost; WEBSOCKET_HOSTNAME names it.
if [ "${HAS_WEBSOCKET:-0}" -eq "1" ]; then
  set -- --websocket-host localhost "$@"
fi
if [ -n "${WEBSOCKET_HOSTNAME}" ]; then
  set -- --websocket-host "${WEBSOCKET_HOSTNAME}" "$@"
fi
if [ -n "${WEBSOCKET_PORT}" ]; then
  set -- --websocket-port "${WEBSOCKET_PORT}" "$@"
fi
if [ -n "${TMATE_SESSIONS_DIR}" ]; then
  set -- --sessions-dir "${TMATE_SESSIONS_DIR}" "$@"
fi

exec tmate-server-rs "$@"
