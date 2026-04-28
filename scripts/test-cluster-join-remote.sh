#!/usr/bin/env bash
# ============================================================
# scripts/test-cluster-join-remote.sh — live validation of
# the CLI's `cluster join <user@host[:port]>` *behavior*
# ============================================================
#
# The CLI binary itself can't be scripted reliably right now: a
# pre-existing bug in the persistent-SSH bridge means responses
# don't flush back to the client until stdin EOFs (only triggers
# when no pty is allocated, which is exactly the
# Stdio::piped + headless case). That's an orthogonal issue —
# unrelated to Commit C — so this harness validates the same
# logic at the protocol level instead, using one-shot ssh
# pipes per RPC (which work fine).
#
# The flow mirrors crates/sftpflow-cli/src/commands.rs's
# cluster_join_remote() exactly:
#
#   1. ClusterMintToken         — single-use HMAC token
#   2. ClusterGetCa             — fetch CA cert PEM (Commit C addition)
#   3. ClusterStatus            — read seed advertise + initial size
#   4. ssh user@host[:port]     — pipe passphrase + CA, run
#                                 nohup sftpflowd join … on the joiner
#   5. ClusterStatus poll       — confirm membership grew
#
# Targets the 4-node cluster from docker/compose.cluster.yml: nodes
# 1-3 are the existing voters, node 4 (port 2234) mounts an alternate
# sshd_config that drops the ForceCommand so we get a real shell.
#
# Exit 0 on PASS, 1 on any step failure.

set -euo pipefail

SSH_KEY="${HOME}/.sftpflow-test/id_ed25519"
KNOWN_HOSTS="${HOME}/.sftpflow-test/cluster_known_hosts"
SEED_HOST="localhost"
# NOTE: must be the *current Raft leader*. The seed-side join
# handler in M12 PR-B calls add_learner / change_membership which
# openraft requires on the leader; on a non-leader it returns
# "has to forward request to: <leader>" and the join silently
# leaves the joiner stranded. Operator-facing leader forwarding
# is a follow-up bug (separate from this Commit C validation).
# Override with SEED_PORT=<port> when running this script.
SEED_PORT="${SEED_PORT:-2231}"
JOINER_HOST="localhost"
JOINER_PORT=2234
JOINER_USER="sftpflow"
PASSPHRASE="${SFTPFLOW_PASSPHRASE:-cluster-test-passphrase}"

step() { echo "  → $*" >&2; }
ok()   { echo "  ✓ $*" >&2; }
fail() { echo "  ✗ $*" >&2; exit 1; }
banner() {
    {
      echo
      echo "============================================================"
      echo "$*"
      echo "============================================================"
    } >&2
}

# ============================================================
# rpc_one_shot — one NDJSON request via a fresh ssh subprocess
# ============================================================
# Equivalent to RpcClient::call() in commands.rs: open a one-line
# ssh pipe, send the request, read the response, EOF closes ssh.
# Echos the raw response line on stdout.
rpc_one_shot() {
    local req="$1"
    echo "${req}" | ssh -T \
        -i "${SSH_KEY}" \
        -p "${SEED_PORT}" \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o BatchMode=yes \
        sftpflow@"${SEED_HOST}"
}

# ============================================================
# Step 1 — ClusterMintToken
# ============================================================
banner "Step 1 — ClusterMintToken"
step "asking seed (${SEED_HOST}:${SEED_PORT}) for a single-use join token"
mint_raw="$(rpc_one_shot '{"id":1,"method":"cluster_mint_token","params":{"ttl_seconds":600}}')"
TOKEN="$(echo "${mint_raw}" | jq -r '.result.value.token // empty')"
[[ -n "${TOKEN}" ]] || { echo "raw: ${mint_raw}" >&2; fail "no token in response"; }
ok "minted token (length=${#TOKEN})"

# ============================================================
# Step 2 — ClusterGetCa  (the Commit C addition)
# ============================================================
banner "Step 2 — ClusterGetCa"
step "fetching cluster CA cert PEM"
ca_raw="$(rpc_one_shot '{"id":2,"method":"cluster_get_ca","params":null}')"
CA_PEM="$(echo "${ca_raw}" | jq -r '.result.value // empty')"
if ! echo "${CA_PEM}" | grep -q 'BEGIN CERTIFICATE'; then
    echo "raw: ${ca_raw}" >&2
    fail "ca payload is not a PEM certificate"
fi
ok "got CA cert PEM ($(echo "${CA_PEM}" | wc -l) lines)"

# ============================================================
# Step 3 — ClusterStatus (read seed advertise + initial size)
# ============================================================
banner "Step 3 — ClusterStatus"
status_raw="$(rpc_one_shot '{"id":3,"method":"cluster_status","params":null}')"
SEED_SELF_ID="$(echo "${status_raw}" | jq -r '.result.value.self_id')"
SEED_ADVERTISE="$(echo "${status_raw}" | jq -r --argjson sid "${SEED_SELF_ID}" \
    '.result.value.members[] | select(.node_id==$sid) | .advertise_addr')"
INITIAL_SIZE="$(echo "${status_raw}" | jq -r '.result.value.members | length')"
[[ -n "${SEED_ADVERTISE}" ]] || fail "could not extract seed advertise"
ok "seed self_id=${SEED_SELF_ID} advertise=${SEED_ADVERTISE} initial_size=${INITIAL_SIZE}"

# ============================================================
# Step 4 — ssh + drive remote sftpflowd join
# ============================================================
# Mirrors ssh_drive_remote_join() in commands.rs: heredoc script
# reads passphrase off stdin line 1, then CA cert lines until the
# ===END-CA=== sentinel, writes CA to a tmp file, nohup launches
# sftpflowd join with </dev/null + redirected stdio so the daemon
# survives our SSH session closing.
banner "Step 4 — drive remote sftpflowd join via ssh"
step "ssh ${JOINER_USER}@${JOINER_HOST}:${JOINER_PORT} → run sftpflowd join"

REMOTE_SCRIPT='
    set -e
    IFS= read -r SFTPFLOW_PASSPHRASE
    export SFTPFLOW_PASSPHRASE
    CA_FILE="$(mktemp /tmp/sftpflow-join-ca.XXXXXX.crt)"
    while IFS= read -r line; do
        if [ "$line" = "===END-CA===" ]; then break; fi
        printf "%s\n" "$line" >> "$CA_FILE"
    done
    LOG=/tmp/sftpflowd-join.log
    : > "$LOG"
    nohup sftpflowd join '"${SEED_ADVERTISE}"' \
        --token '"${TOKEN}"' \
        --ca-cert-file "$CA_FILE" \
        > "$LOG" 2>&1 < /dev/null &
    DAEMON_PID=$!
    sleep 2
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "sftpflowd join died early; tail of $LOG:" >&2
        tail -20 "$LOG" >&2
        exit 1
    fi
    echo "sftpflowd join running (pid=$DAEMON_PID); log at $LOG"
'

# Pipe stdin to ssh: line 1 = passphrase, then CA lines, then sentinel.
# Pass the script as a positional argument (NOT `sh -s`) so the
# remote `read` calls actually consume stdin.
{
    echo "${PASSPHRASE}"
    echo "${CA_PEM}"
    echo "===END-CA==="
} | ssh -T \
    -i "${SSH_KEY}" \
    -p "${JOINER_PORT}" \
    -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="${KNOWN_HOSTS}" \
    -o BatchMode=yes \
    "${JOINER_USER}@${JOINER_HOST}" \
    "${REMOTE_SCRIPT}" >&2

ok "remote launch returned"

# ============================================================
# Step 5 — Poll ClusterStatus for new member
# ============================================================
banner "Step 5 — poll for new member"
step "waiting up to 30s for cluster to grow from ${INITIAL_SIZE} members"
for i in $(seq 1 30); do
    status_raw="$(rpc_one_shot '{"id":4,"method":"cluster_status","params":null}' 2>/dev/null || echo '')"
    if [[ -n "${status_raw}" ]]; then
        new_size="$(echo "${status_raw}" | jq -r '.result.value.members | length' 2>/dev/null || echo 0)"
        if [[ "${new_size}" -gt "${INITIAL_SIZE}" ]]; then
            ok "cluster grew ${INITIAL_SIZE} → ${new_size} members"
            echo
            echo "Final membership:" >&2
            echo "${status_raw}" | jq '.result.value' >&2
            echo
            echo "============================================================"
            echo "PASS — Commit C cluster join flow works end-to-end"
            echo "============================================================"
            exit 0
        fi
    fi
    sleep 1
done

echo "remote launch log (joiner):" >&2
ssh -i "${SSH_KEY}" -p "${JOINER_PORT}" \
    -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="${KNOWN_HOSTS}" \
    -o BatchMode=yes \
    "${JOINER_USER}@${JOINER_HOST}" \
    "tail -50 /tmp/sftpflowd-join.log 2>&1 || true" >&2

fail "cluster did not grow within 30s"
