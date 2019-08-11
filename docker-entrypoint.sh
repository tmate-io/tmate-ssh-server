#!/bin/sh
set -e

if [ "${USE_PROXY}" == "1" ]; then
  exec tmate-ssh-server -p 2200 -k ${SSH_KEYS_PATH} -h ${SSH_HOSTNAME} -x localhost
else
  exec tmate-ssh-server -p 2200 -k ${SSH_KEYS_PATH} -h ${SSH_HOSTNAME}
fi
