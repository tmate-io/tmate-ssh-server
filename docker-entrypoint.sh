#!/bin/sh
set -e

if [ "${USE_PROXY}" == "1" ]; then
  set -- -x localhost "$@"
fi

if [ ! -z "${HOSTNAME}" ]; then
  set -- -h "${HOSTNAME}" "$@"
fi

exec tmate-ssh-server -p 2200 -k ${SSH_KEYS_PATH} "$@"
