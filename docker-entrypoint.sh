#!/bin/sh
set -e

SSH_KEYS_PATH="${DOCKER_BIND_MOUNT}/${SSH_KEYS_PATH}"

gen_key() {
  keytype=$1
  ks="${keytype}_"
  key="${SSH_KEYS_PATH}/ssh_host_${ks}key"
  if [ ! -e "${key}" ] ; then
    ssh-keygen -t ${keytype} -f "${key}" -N ''
    chown -R "${DOCKER_RUN_USER}" "${key}"
    chown -R "${DOCKER_RUN_USER}" "${key}.pub"
    echo ""
  fi
}

get_key_sig() {
  key="${1}"

  ssh-keygen -l -E SHA256 -f $key | cut -d ' ' -f 2
}


create_keys() {
  gen_key rsa
  gen_key ecdsa
  gen_key ed25519

}

display_client_tmate_conf() {
  RSA_SIG=$(get_key_sig "${SSH_KEYS_PATH}/ssh_host_rsa_key.pub")
  ECDSA_SIG=$(get_key_sig "${SSH_KEYS_PATH}/ssh_host_ecdsa_key.pub")
  ED25519_SIG=$(get_key_sig "${SSH_KEYS_PATH}/ssh_host_ed25519_key.pub")

  echo "You may use the following settings this in your .tmate.conf:"
  echo ""
  echo "set -g tmate-server-host $TMATE_SERVER_IP"            | tee    ${DOCKER_BIND_MOUNT}/tmate.conf
  echo "set -g tmate-server-port $SSH_PORT_LISTEN"            | tee -a ${DOCKER_BIND_MOUNT}/tmate.conf
  echo "set -g tmate-server-rsa-fingerprint $RSA_SIG"         | tee -a ${DOCKER_BIND_MOUNT}/tmate.conf
  echo "set -g tmate-server-ecdsa-fingerprint $ECDSA_SIG"     | tee -a ${DOCKER_BIND_MOUNT}/tmate.conf
  echo "set -g tmate-server-ed25519-fingerprint $ED25519_SIG" | tee -a ${DOCKER_BIND_MOUNT}/tmate.conf
}


if [ "${USE_PROXY_PROTOCOL}" == "1" ]; then
  set -- -x "$@"
fi

if [ "${HAS_WEBSOCKET}" == "1" ]; then
  set -- -w localhost "$@"
fi

if [ ! -z "${SSH_HOSTNAME}" ]; then
  set -- -h "${SSH_HOSTNAME}" "$@"
fi

create_keys
display_client_tmate_conf

exec tmate-ssh-server -p ${SSH_PORT_LISTEN} -q ${SSH_PORT_ADVERTISE} -k ${SSH_KEYS_PATH} "$@"
