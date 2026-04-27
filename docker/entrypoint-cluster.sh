#!/bin/sh
# ============================================================
# docker/entrypoint-cluster.sh - cluster-aware entrypoint
# ============================================================
#
# Used by docker/compose.cluster.yml — the multi-process M12
# integration test environment. Differs from entrypoint.sh in
# one important way: the daemon is only auto-started after the
# node has been bootstrapped (init or join), which is detected
# by the presence of <state_dir>/node.json.
#
# Lifecycle:
#
#   First container start (no node.json yet):
#     1. Set up sshd host keys.
#     2. Install authorized_keys for the sftpflow user.
#     3. Start sshd in the foreground. No daemon yet.
#     4. Operator runs `docker exec -d <ctr> sftpflowd init|join ...`
#        from the host. That detached process writes node.json +
#        certs and enters the NDJSON serve loop for the rest of
#        the container's lifetime.
#
#   Subsequent container restarts (node.json present):
#     1-2. Same as above.
#     3.   Background `sftpflowd run` (cluster-mode restart;
#          openraft replays sled and rejoins peers).
#     4.   Foreground sshd.
#
# This split lets the integration test exercise the real init/join
# operator UX while still getting transparent recovery on container
# restart — which is exactly the failover scenario the test runs.

set -eu

STATE_DIR="/var/lib/sftpflow"
SOCKET="/run/sftpflow/sftpflow.sock"
HOSTKEY_DIR="/etc/ssh/keys"
AUTHORIZED_KEYS_SRC="/etc/sftpflow/authorized_keys"
AUTHORIZED_KEYS_DST="/home/sftpflow/.ssh/authorized_keys"
NODE_JSON="${STATE_DIR}/node.json"

log() {
    printf '[entrypoint-cluster] %s\n' "$*" >&2
}

# ------------------------------------------------------------
# Step 1: sshd host keys (idempotent across restarts via volume)
# ------------------------------------------------------------
ensure_host_keys() {
    log "checking sshd host keys in ${HOSTKEY_DIR}"
    if [ ! -f "${HOSTKEY_DIR}/ssh_host_ed25519_key" ]; then
        log "generating ed25519 host key"
        ssh-keygen -t ed25519 -f "${HOSTKEY_DIR}/ssh_host_ed25519_key" -N "" -q
    fi
    if [ ! -f "${HOSTKEY_DIR}/ssh_host_rsa_key" ]; then
        log "generating rsa host key"
        ssh-keygen -t rsa -b 3072 -f "${HOSTKEY_DIR}/ssh_host_rsa_key" -N "" -q
    fi
    chmod 600 "${HOSTKEY_DIR}"/ssh_host_*_key
    chmod 644 "${HOSTKEY_DIR}"/ssh_host_*_key.pub
}

# ------------------------------------------------------------
# Step 2: authorized_keys for the sftpflow SSH user
# ------------------------------------------------------------
install_authorized_keys() {
    if [ ! -f "${AUTHORIZED_KEYS_SRC}" ]; then
        log "WARNING: ${AUTHORIZED_KEYS_SRC} not found"
        log "         run 'make test-keygen' on the host and retry"
        : > "${AUTHORIZED_KEYS_DST}"
    else
        log "installing authorized_keys from ${AUTHORIZED_KEYS_SRC}"
        cp "${AUTHORIZED_KEYS_SRC}" "${AUTHORIZED_KEYS_DST}"
    fi
    chown sftpflow:sftpflow "${AUTHORIZED_KEYS_DST}"
    chmod 600 "${AUTHORIZED_KEYS_DST}"
}

# ------------------------------------------------------------
# Step 3: cluster-mode restart, only when node.json exists
# ------------------------------------------------------------
# Mirrors entrypoint.sh's start_daemon, but uses `sftpflowd run`
# (which auto-detects cluster mode from node.json) and refuses
# to start when node.json hasn't been written yet — that's the
# operator's signal that init/join hasn't happened.
maybe_start_daemon() {
    if [ ! -f "${NODE_JSON}" ]; then
        log "no ${NODE_JSON} yet — daemon will start when init/join writes it"
        log "trigger via: docker exec -d <ctr> sftpflowd init|join ..."
        return 0
    fi

    log "${NODE_JSON} present — bringing daemon back up in cluster mode"
    su -s /bin/sh sftpflow -c "
        export SFTPFLOW_CONFIG='${STATE_DIR}/config.yaml'
        export RUST_LOG='${RUST_LOG:-info}'
        export SFTPFLOW_PASSPHRASE='${SFTPFLOW_PASSPHRASE:-}'
        cd '${STATE_DIR}'
        exec sftpflowd run --socket unix:${SOCKET}
    " &
    DAEMON_PID=$!
    log "sftpflowd pid=${DAEMON_PID}"

    # Wait for the socket to appear so SSH-bridge clients don't race
    # the daemon. Cap at ~15s; cluster restart is normally <5s but
    # election timeouts can push it out under load.
    i=0
    while [ ! -S "${SOCKET}" ] && [ "${i}" -lt 150 ]; do
        if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
            log "sftpflowd exited during startup"
            wait "${DAEMON_PID}" || true
            exit 1
        fi
        sleep 0.1
        i=$((i + 1))
    done

    if [ ! -S "${SOCKET}" ]; then
        log "timed out waiting for ${SOCKET}"
        exit 1
    fi
    log "daemon socket ready"
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
ensure_host_keys
install_authorized_keys
maybe_start_daemon

log "starting sshd in foreground"
exec /usr/sbin/sshd -D -e
