#!/usr/bin/env bash
set -e

DOCKER_IMAGE_NAME="tmate-ssh-server"
DOCKER_IMAGE_VERSION="${DOCKER_IMAGE_VERSION:-latest}"
DOCKER_BIND_MOUNT="/docker"
DOCKER_RUN_USER="${DOCKER_RUN_USER:-$(id -u)}"

# this should be set to either you external ip address or an ip address
# that your team can reach
TMATE_SERVER_IP="${TMATE_SERVER_IP:-127.0.0.1}"

# tmate-ssh-server env vars
SSH_PORT_LISTEN=${SSH_PORT_LISTEN:-2200}
SSH_PORT_ADVERTIZE=${SSH_PORT_ADVERTIZE:-${SSH_PORT_LISTEN}}
SSH_PORT_ADVERTISE=${SSH_PORT_ADVERTISE:-${SSH_PORT_ADVERTIZE}}
SSH_KEYS_PATH="${SSH_KEYS_PATH:-/keys}"

mkdir -p "${SSH_KEYS_PATH#/}"

docker build -t ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION} .

ID=$(docker ps -f name=${DOCKER_IMAGE_NAME} -q)

[ -z "${ID}" ] || docker rm -vf "${ID}"

docker run                                        \
  -d                                              \
  --cap-add SYS_ADMIN                             \
  -p ${SSH_PORT_ADVERTIZE}:${SSH_PORT_ADVERTIZE}  \
  -e SSH_PORT_ADVERTIZE=${SSH_PORT_ADVERTIZE}     \
  -e SSH_KEYS_PATH=${SSH_KEYS_PATH}               \
  -e TMATE_SERVER_IP=${TMATE_SERVER_IP}           \
  -e DOCKER_BIND_MOUNT=${DOCKER_BIND_MOUNT}       \
  -e DOCKER_RUN_USER=${DOCKER_RUN_USER}           \
  --name "${DOCKER_IMAGE_NAME}"                   \
  -v "${PWD}:${DOCKER_BIND_MOUNT}"                \
  --hostname "${TMATE_SERVER_IP}"                 \
  ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}

echo
echo
[ -f tmate.conf ] && cat tmate.conf || (echo "ERR: no tmate.conf was generated" && exit 1)
echo
