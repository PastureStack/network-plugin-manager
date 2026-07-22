#!/bin/bash
set -e

for i in $(curl -s --unix-socket /var/run/docker.sock http://localhost/info | jq -r .DockerRootDir) /var/lib/docker /run /var/run; do
    for m in $(tac /proc/mounts | awk '{print $2}' | grep ^${i}/); do
        umount $m || true
    done
done

if [ -z "${DOCKER_API_VERSION}" ]; then
    DOCKER_API_VERSION=$(curl -fsS --unix-socket /var/run/docker.sock http://localhost/version | jq -r '.ApiVersion // empty' || true)
    if [ -n "${DOCKER_API_VERSION}" ]; then
        export DOCKER_API_VERSION
        echo "Using Docker API version ${DOCKER_API_VERSION} reported by host daemon"
    else
        unset DOCKER_API_VERSION
        echo "Docker API version not detected; using Docker client default"
    fi
fi

NETWORK_AGENT_IDS=$(curl -fsS --unix-socket /var/run/docker.sock \
    --get \
    --data-urlencode 'filters={"label":["io.rancher.container.system=NetworkAgent"]}' \
    http://localhost/containers/json | jq -r '.[].Id')

for id in ${NETWORK_AGENT_IDS}; do
    curl -fsS -X DELETE --unix-socket /var/run/docker.sock \
        "http://localhost/containers/${id}?force=1&v=1" >/dev/null || true
done

exec "$@"
