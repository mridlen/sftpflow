#!/usr/bin/env bash
# ============================================================
# scripts/test-cluster.sh — M12 multi-process integration test
# ============================================================
#
# Drives docker/compose.cluster.yml through the full M12 PR-B
# acceptance scenario:
#
#   Phase 1 — Bootstrap:
#     1. Start the 3-node compose env.
#     2. Run `sftpflowd init` on node 1 (detached).
#     3. Mint a join token via the SSH bridge.
#     4. Copy the cluster CA cert from node 1 onto nodes 2/3.
#     5. Run `sftpflowd join` on nodes 2 and 3 (detached).
#     6. Verify `cluster status` on each node reports all 3 members
#        with a single agreed-upon leader.
#
#   Phase 2 — Failover:
#     7. Identify the current leader and stop its container.
#     8. Within 15s, verify a survivor reports a new leader.
#     9. Restart the stopped container.
#    10. Verify it rejoins without operator intervention (entrypoint
#        sees node.json and runs `sftpflowd run` → cluster restart).
#
# Exit codes:
#     0  every phase passed
#     1  a verification step failed; logs printed inline
#
# Dependencies:
#     bash, docker (with compose v2), ssh, jq
#     ~/.sftpflow-test/id_ed25519 (run `make test-keygen` first)

set -euo pipefail

# ============================================================
# Constants
# ============================================================

COMPOSE_FILE="docker/compose.cluster.yml"
SSH_KEY="${HOME}/.sftpflow-test/id_ed25519"
KNOWN_HOSTS="${HOME}/.sftpflow-test/cluster_known_hosts"

CONTAINERS=(sftpflow-cluster-1 sftpflow-cluster-2 sftpflow-cluster-3)
HOSTNAMES=(sftpflow-1 sftpflow-2 sftpflow-3)
SSH_PORTS=(2231 2232 2233)
NODE_IDS=(1 2 3)

# Internal Raft port (same on every node — they reach each other via
# docker DNS, so port reuse across nodes is fine and keeps configs
# uniform). Not exposed to the host.
RAFT_PORT=7900

# Wait budgets. Cluster bootstrap is normally <2s; election timeout
# is ~500ms-1s. These are loose to absorb CI noise.
JOIN_WAIT_SECS=20
ELECTION_WAIT_SECS=15
RESTART_WAIT_SECS=20

# ============================================================
# Logging
# ============================================================

# All status messages go to stderr so functions can use stdout for
# data (e.g. phase1_mint_token returning the minted token) without
# the banner/step/ok lines getting captured by command substitution.
banner() {
    {
        echo
        echo "============================================================"
        echo "$*"
        echo "============================================================"
    } >&2
}

step() { echo "  → $*" >&2; }
ok()   { echo "  ✓ $*" >&2; }
fail() { echo "  ✗ $*" >&2; exit 1; }

# ============================================================
# Preflight
# ============================================================

preflight() {
    banner "Preflight"

    for cmd in docker ssh jq; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            fail "missing required command: ${cmd}"
        fi
    done
    ok "docker, ssh, jq all present"

    if [[ ! -f "${SSH_KEY}" ]]; then
        fail "no client SSH key at ${SSH_KEY} — run 'make test-keygen' first"
    fi
    ok "client SSH key found at ${SSH_KEY}"

    # known_hosts is per-test-env so a stale entry from the
    # single-node env doesn't poison the cluster test. Fresh file
    # each run + StrictHostKeyChecking=accept-new.
    : > "${KNOWN_HOSTS}"
}

# ============================================================
# Compose lifecycle
# ============================================================

compose_up() {
    banner "Starting compose env (3 nodes)"
    docker compose -f "${COMPOSE_FILE}" up -d --build

    # Wait for sshd via a plain TCP probe. We can't SSH-and-run a
    # command here yet — sshd's ForceCommand'd shell tries to dial
    # a unix socket that doesn't exist until after `sftpflowd init`,
    # so the SSH session would fail even when sshd itself is fine.
    # bash's /dev/tcp gives us a portable connect-only check.
    step "waiting for sshd to bind on each node"
    for i in 0 1 2; do
        local port="${SSH_PORTS[${i}]}"
        local tries=0
        while ! (exec 3<>/dev/tcp/localhost/"${port}") 2>/dev/null; do
            tries=$((tries + 1))
            if [[ "${tries}" -gt 30 ]]; then
                fail "sshd on node $((i+1)) (port ${port}) never bound"
            fi
            sleep 1
        done
        ok "sshd listening on node $((i+1)) (port ${port})"
    done
}

compose_down() {
    banner "Tearing down compose env"
    docker compose -f "${COMPOSE_FILE}" down -v
}

# ============================================================
# RPC helpers (NDJSON via SSH bridge)
# ============================================================

# Send one NDJSON request to a node via the SSH bridge and print
# the raw response line. Args: <node-index 0..2> <request-json>
rpc_call() {
    local idx="${1}"
    local req="${2}"
    echo "${req}" | ssh -T \
        -i "${SSH_KEY}" \
        -p "${SSH_PORTS[${idx}]}" \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o BatchMode=yes \
        sftpflow@localhost
}

# Fetch ClusterStatus from a node (idx 0..2) and print the JSON
# value (the inner "result.value" object). Empty string if the
# call failed.
cluster_status_json() {
    local idx="${1}"
    local raw
    raw="$(rpc_call "${idx}" '{"id":1,"method":"cluster_status","params":null}' 2>/dev/null || true)"
    if [[ -z "${raw}" ]]; then
        echo ""
        return
    fi
    # Take the last non-empty line (sshd may emit warnings before the
    # NDJSON body in some configs) and pull out the result payload.
    echo "${raw}" \
      | grep -v '^$' \
      | tail -1 \
      | jq -c 'if .error then null else .result.value end' 2>/dev/null \
      || echo ""
}

# ============================================================
# Phase 1 — Bootstrap
# ============================================================

phase1_init_node1() {
    banner "Phase 1.1 — Bootstrap node 1"
    step "running 'sftpflowd init' on ${CONTAINERS[0]} (detached)"
    docker exec -d \
        -e SFTPFLOW_PASSPHRASE=cluster-test-passphrase \
        "${CONTAINERS[0]}" \
        su -s /bin/sh sftpflow -c "
            export SFTPFLOW_PASSPHRASE='cluster-test-passphrase'
            export RUST_LOG=info
            cd /var/lib/sftpflow
            exec sftpflowd init \
                --node-id 1 \
                --bind 0.0.0.0:${RAFT_PORT} \
                --advertise ${HOSTNAMES[0]}:${RAFT_PORT} \
                --label bootstrap \
                --socket unix:/run/sftpflow/sftpflow.sock
        "

    step "waiting for node.json on node 1"
    local tries=0
    until docker exec "${CONTAINERS[0]}" test -f /var/lib/sftpflow/node.json 2>/dev/null; do
        tries=$((tries + 1))
        if [[ "${tries}" -gt 30 ]]; then
            fail "node 1 did not write node.json within 30s"
        fi
        sleep 1
    done
    ok "node 1 wrote node.json"

    step "waiting for unix socket on node 1"
    tries=0
    until docker exec "${CONTAINERS[0]}" test -S /run/sftpflow/sftpflow.sock 2>/dev/null; do
        tries=$((tries + 1))
        if [[ "${tries}" -gt 30 ]]; then
            fail "node 1 daemon socket never appeared"
        fi
        sleep 1
    done
    ok "node 1 daemon socket ready"
}

phase1_mint_token() {
    banner "Phase 1.2 — Mint join token via node 1's SSH bridge"
    local raw json token
    raw="$(rpc_call 0 '{"id":1,"method":"cluster_mint_token","params":{"ttl_seconds":600}}')"
    json="$(echo "${raw}" | grep -v '^$' | tail -1)"
    token="$(echo "${json}" | jq -r '.result.value.token // empty')"
    if [[ -z "${token}" ]]; then
        echo "raw response: ${raw}" >&2
        fail "mint_token returned no token"
    fi
    ok "minted token (length=${#token})"
    echo "${token}"
}

# Copy /var/lib/sftpflow/cluster/ca.crt out of node 1 and into the
# joiner's filesystem under /etc/sftpflow/ca.crt — the path matches
# the container layout the join command will reference.
copy_ca_to_joiner() {
    local joiner_idx="${1}"
    local tmp
    tmp="$(mktemp)"
    docker exec "${CONTAINERS[0]}" cat /var/lib/sftpflow/cluster/ca.crt > "${tmp}"
    if ! grep -q 'BEGIN CERTIFICATE' "${tmp}"; then
        rm -f "${tmp}"
        fail "node 1's ca.crt does not look like a PEM certificate"
    fi
    docker cp "${tmp}" "${CONTAINERS[${joiner_idx}]}:/etc/sftpflow/ca.crt"
    rm -f "${tmp}"
}

phase1_join_node() {
    local idx="${1}"
    local node_id="${NODE_IDS[${idx}]}"
    local hostname="${HOSTNAMES[${idx}]}"
    local container="${CONTAINERS[${idx}]}"
    local token="${2}"

    step "copying CA cert from node 1 onto ${container}"
    copy_ca_to_joiner "${idx}"

    step "running 'sftpflowd join' on ${container} (detached)"
    docker exec -d \
        -e SFTPFLOW_PASSPHRASE=cluster-test-passphrase \
        "${container}" \
        su -s /bin/sh sftpflow -c "
            export SFTPFLOW_PASSPHRASE='cluster-test-passphrase'
            export RUST_LOG=info
            cd /var/lib/sftpflow
            exec sftpflowd join ${HOSTNAMES[0]}:${RAFT_PORT} \
                --token '${token}' \
                --ca-cert-file /etc/sftpflow/ca.crt \
                --node-id ${node_id} \
                --bind 0.0.0.0:${RAFT_PORT} \
                --advertise ${hostname}:${RAFT_PORT} \
                --label joiner-${node_id} \
                --socket unix:/run/sftpflow/sftpflow.sock
        "

    step "waiting for node ${node_id} to write node.json + open socket"
    local tries=0
    until docker exec "${container}" test -f /var/lib/sftpflow/node.json 2>/dev/null \
       && docker exec "${container}" test -S /run/sftpflow/sftpflow.sock 2>/dev/null; do
        tries=$((tries + 1))
        if [[ "${tries}" -gt JOIN_WAIT_SECS ]]; then
            fail "node ${node_id} did not finish join within ${JOIN_WAIT_SECS}s"
        fi
        sleep 1
    done
    ok "node ${node_id} joined"
}

# Poll cluster_status from every node until they all report 3
# members and a leader, or time out.
wait_for_three_node_convergence() {
    banner "Phase 1.3 — Wait for cluster to converge to 3 members"
    local tries=0
    while [[ "${tries}" -lt JOIN_WAIT_SECS ]]; do
        local all_ok=1
        local leader_id=""
        for i in 0 1 2; do
            local json
            json="$(cluster_status_json "${i}")"
            if [[ -z "${json}" || "${json}" == "null" ]]; then
                all_ok=0
                break
            fi
            local n_members
            n_members="$(echo "${json}" | jq '.members | length')"
            local node_leader
            node_leader="$(echo "${json}" | jq -r '.leader_id // "none"')"
            if [[ "${n_members}" != "3" || "${node_leader}" == "none" ]]; then
                all_ok=0
                break
            fi
            if [[ -z "${leader_id}" ]]; then
                leader_id="${node_leader}"
            elif [[ "${leader_id}" != "${node_leader}" ]]; then
                all_ok=0
                break
            fi
        done
        if [[ "${all_ok}" == "1" ]]; then
            ok "all 3 nodes report 3 members; agreed leader = ${leader_id}"
            return 0
        fi
        tries=$((tries + 1))
        sleep 1
    done
    print_status_dump
    fail "cluster did not converge to 3 members within ${JOIN_WAIT_SECS}s"
}

# ============================================================
# Phase 2 — Failover
# ============================================================

# Read leader_id off any survivor node. Pass an array of node
# indices to query. Echos the leader_id (numeric) or empty.
read_leader_from_survivors() {
    local survivors=("$@")
    for idx in "${survivors[@]}"; do
        local json
        json="$(cluster_status_json "${idx}")"
        if [[ -n "${json}" && "${json}" != "null" ]]; then
            local lid
            lid="$(echo "${json}" | jq -r '.leader_id // "none"')"
            if [[ "${lid}" != "none" && -n "${lid}" ]]; then
                echo "${lid}"
                return 0
            fi
        fi
    done
    echo ""
}

phase2_kill_leader() {
    banner "Phase 2.1 — Stop the leader, expect a new election"

    local json leader_id leader_idx
    json="$(cluster_status_json 0)"
    leader_id="$(echo "${json}" | jq -r '.leader_id // "none"')"
    if [[ "${leader_id}" == "none" || -z "${leader_id}" ]]; then
        fail "could not read leader_id from cluster_status"
    fi
    leader_idx=$((leader_id - 1))
    ok "current leader = node_id ${leader_id} (${CONTAINERS[${leader_idx}]})"

    step "stopping ${CONTAINERS[${leader_idx}]}"
    docker stop "${CONTAINERS[${leader_idx}]}" >/dev/null

    # Survivors = the other two indices
    local survivors=()
    for i in 0 1 2; do
        if [[ "${i}" != "${leader_idx}" ]]; then
            survivors+=("${i}")
        fi
    done

    step "polling survivors for a new leader (budget ${ELECTION_WAIT_SECS}s)"
    local tries=0 new_leader=""
    while [[ "${tries}" -lt ELECTION_WAIT_SECS ]]; do
        new_leader="$(read_leader_from_survivors "${survivors[@]}")"
        if [[ -n "${new_leader}" && "${new_leader}" != "${leader_id}" ]]; then
            ok "new leader = node_id ${new_leader} (was node_id ${leader_id})"
            # Stash via files so the restart phase can pick them up
            # without resorting to a global var across functions.
            echo "${leader_idx}" > /tmp/sftpflow-cluster-killed-idx
            echo "${leader_id}"  > /tmp/sftpflow-cluster-killed-id
            return 0
        fi
        tries=$((tries + 1))
        sleep 1
    done
    print_status_dump
    fail "no new leader elected within ${ELECTION_WAIT_SECS}s (still ${new_leader:-<none>})"
}

phase2_restart_killed() {
    banner "Phase 2.2 — Restart the killed node, expect transparent rejoin"
    local killed_idx killed_id
    killed_idx="$(cat /tmp/sftpflow-cluster-killed-idx)"
    killed_id="$(cat /tmp/sftpflow-cluster-killed-id)"

    step "starting ${CONTAINERS[${killed_idx}]}"
    docker start "${CONTAINERS[${killed_idx}]}" >/dev/null

    step "waiting for node ${killed_id}'s daemon socket to come back"
    local tries=0
    until docker exec "${CONTAINERS[${killed_idx}]}" \
            test -S /run/sftpflow/sftpflow.sock 2>/dev/null; do
        tries=$((tries + 1))
        if [[ "${tries}" -gt RESTART_WAIT_SECS ]]; then
            fail "node ${killed_id} daemon did not come back within ${RESTART_WAIT_SECS}s"
        fi
        sleep 1
    done
    ok "node ${killed_id} daemon socket back"

    step "verifying all 3 nodes report 3 members again"
    tries=0
    while [[ "${tries}" -lt RESTART_WAIT_SECS ]]; do
        local all_ok=1
        for i in 0 1 2; do
            local json
            json="$(cluster_status_json "${i}")"
            if [[ -z "${json}" || "${json}" == "null" ]]; then
                all_ok=0; break
            fi
            local n
            n="$(echo "${json}" | jq '.members | length')"
            if [[ "${n}" != "3" ]]; then
                all_ok=0; break
            fi
        done
        if [[ "${all_ok}" == "1" ]]; then
            ok "all 3 nodes report 3 members — rejoin complete"
            return 0
        fi
        tries=$((tries + 1))
        sleep 1
    done
    print_status_dump
    fail "cluster did not return to 3 members within ${RESTART_WAIT_SECS}s"
}

# ============================================================
# Diagnostics
# ============================================================

print_status_dump() {
    echo
    echo "---- cluster_status from each node (diagnostic) ----" >&2
    for i in 0 1 2; do
        echo "node $((i+1)) (port ${SSH_PORTS[${i}]}):" >&2
        cluster_status_json "${i}" | jq . >&2 || true
    done
    echo "---- end diagnostic dump ----" >&2
    echo
}

# ============================================================
# Main
# ============================================================

main() {
    preflight
    compose_up

    phase1_init_node1
    local token
    token="$(phase1_mint_token | tail -1)"
    phase1_join_node 1 "${token}"
    phase1_join_node 2 "${token}"
    wait_for_three_node_convergence

    phase2_kill_leader
    phase2_restart_killed

    banner "ALL PHASES PASSED"
    echo "Cluster is left running so you can poke at it. To tear down:"
    echo "    make cluster-down"
}

main "$@"
