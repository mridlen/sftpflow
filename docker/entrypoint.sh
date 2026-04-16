#!/bin/sh
# ============================================================
# docker/entrypoint.sh - bring up sftpflowd + sshd
# ============================================================
#
# Runs as PID 1 inside the sftpflow-server container. Three jobs:
#
#   1. Generate persistent sshd host keys on first boot (so the
#      client's known_hosts stays stable across container restarts).
#   2. Install the test client's public key(s) as authorized_keys
#      for the sftpflow user (mounted read-only from the host).
#   3. Start sftpflowd as the sftpflow user in the background, then
#      exec sshd in the foreground. The ForceCommand'd sftpflow-shell
#      will dial the daemon's unix socket at /run/sftpflow/.
#
# POSIX sh on purpose - no bashisms, runs on the bookworm-slim image
# without any extra packages.

set -eu

SOCKET="/run/sftpflow/sftpflow.sock"
CONFIG_DIR="/var/lib/sftpflow"
HOSTKEY_DIR="/etc/ssh/keys"
AUTHORIZED_KEYS_SRC="/etc/sftpflow/authorized_keys"
AUTHORIZED_KEYS_DST="/home/sftpflow/.ssh/authorized_keys"

log() {
    # Prefixed so messages stand out from sshd/sftpflowd output in
    # `docker logs`. stderr keeps them unbuffered.
    printf '[entrypoint] %s\n' "$*" >&2
}

# ------------------------------------------------------------
# Step 1: host keys
# ------------------------------------------------------------
# ssh-keygen creates the key only if the file is missing, so this
# is idempotent across container restarts when /etc/ssh/keys is a
# named volume.
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
# Step 2: authorized_keys for the sftpflow user
# ------------------------------------------------------------
# Compose mounts the host's docker/test-keys/id_ed25519.pub here.
# If the mount is missing we keep running (sshd will reject every
# connection) so the operator sees the empty-authorized_keys error
# in the log rather than a silent container crash-loop.
install_authorized_keys() {
    if [ ! -f "${AUTHORIZED_KEYS_SRC}" ]; then
        log "WARNING: ${AUTHORIZED_KEYS_SRC} not found"
        log "         run 'make test-keygen' on the host and retry"
        # Write an empty file so sshd's AuthorizedKeysFile path exists.
        : > "${AUTHORIZED_KEYS_DST}"
    else
        log "installing authorized_keys from ${AUTHORIZED_KEYS_SRC}"
        cp "${AUTHORIZED_KEYS_SRC}" "${AUTHORIZED_KEYS_DST}"
    fi
    chown sftpflow:sftpflow "${AUTHORIZED_KEYS_DST}"
    chmod 600 "${AUTHORIZED_KEYS_DST}"
}

# ------------------------------------------------------------
# Step 3: sftpflowd (daemon) in the background
# ------------------------------------------------------------
# Runs as the sftpflow user so the unix socket is owned by the same
# uid that sftpflow-shell runs under (no cross-user socket perms).
start_daemon() {
    log "starting sftpflowd on unix:${SOCKET}"
    # Pin the daemon's config file to the persistent volume at
    # ${CONFIG_DIR}/config.yaml. Without SFTPFLOW_CONFIG, sftpflow-core
    # falls back to $HOME/.sftpflow/config.yaml (inside the container's
    # ephemeral layer) and mutations would vanish on restart.
    # RUST_LOG is forwarded from the container env when set.
    su -s /bin/sh sftpflow -c "
        export SFTPFLOW_CONFIG='${CONFIG_DIR}/config.yaml'
        export RUST_LOG='${RUST_LOG:-info}'
        cd '${CONFIG_DIR}'
        exec sftpflowd --socket unix:${SOCKET}
    " &
    DAEMON_PID=$!
    log "sftpflowd pid=${DAEMON_PID}"

    # Wait for the socket to appear so sshd clients don't race the daemon
    # on the very first connection. Cap at ~10s to avoid hanging forever
    # if the daemon crashed at startup.
    i=0
    while [ ! -S "${SOCKET}" ] && [ "${i}" -lt 100 ]; do
        # Did the daemon die already? If so, bail out fast with its exit
        # code so docker restart-policies can see the failure.
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
ensure_host_keys        # sshd host keys (section: Step 1)
install_authorized_keys # client pubkey (section: Step 2)
start_daemon            # sftpflowd bg   (section: Step 3)

log "starting sshd in foreground"
# -D: don't fork. -e: log to stderr (captured by docker logs).
exec /usr/sbin/sshd -D -e
