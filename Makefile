# ============================================================
# Makefile — SFTPflow developer targets
# ============================================================
#
# The integration test environment (milestone 6) is defined in
# docker/compose.test.yml. These targets are intended to be run
# from WSL2 on Windows — the target platform is Linux, so the
# Makefile uses POSIX commands only (no PowerShell fallbacks).
#
# Quick start:
#   make test-keygen   # one-time: generate a client SSH keypair
#   make test-build    # build the sftpflow-server image
#   make test-up       # start the test env (server + 2 peers + mailhog)
#   make test-shell    # ssh into the daemon via the bridge
#   make test-down     # tear it all down

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
# Compose file path relative to repo root.
COMPOSE_FILE := docker/compose.test.yml
# Cluster integration test compose file (M12 multi-process env).
CLUSTER_COMPOSE_FILE := docker/compose.cluster.yml

# `docker compose` (v2 plugin) is the canonical form; fall back to the
# older `docker-compose` only if v2 isn't present.
COMPOSE := $(shell command -v docker >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# ---- Key storage ----
# The *private* key must live on a filesystem that honours POSIX
# permissions — ssh refuses to use a world-readable private key.
# When the repo is on /mnt/c (Dropbox on Windows, via WSL 9p), chmod
# is a no-op there, so we store the private key in the WSL-native
# home directory and only copy the public half into the repo tree
# where the compose bind-mount can reach it.
PRIV_KEY_DIR := $(HOME)/.sftpflow-test
PRIV_KEY     := $(PRIV_KEY_DIR)/id_ed25519
PRIV_KEY_PUB := $(PRIV_KEY).pub

# Public key bind-mounted read-only into the container as the
# sftpflow user's authorized_keys. Gitignored.
PUB_KEY_DIR  := docker/test-keys
PUB_KEY      := $(PUB_KEY_DIR)/id_ed25519.pub

# Host port the sftpflow-server's sshd is exposed on. Keep in sync
# with docker/compose.test.yml.
SFTPFLOW_SSH_PORT := 2222

# ------------------------------------------------------------
# Phony target declarations
# ------------------------------------------------------------
.PHONY: help \
        test-keygen test-build test-up test-down test-restart \
        test-logs test-status test-shell test-ping test-clean \
        cluster-build cluster-up cluster-down cluster-clean \
        cluster-logs cluster-status cluster-test

# Default target: print the list of available test- commands.
help:
	@echo "SFTPflow test environment targets:"
	@echo ""
	@echo "  make test-keygen   Generate $(PRIV_KEY)"
	@echo "  make test-build    Build the sftpflow-server image"
	@echo "  make test-up       Start the test env (detached)"
	@echo "  make test-down     Stop and remove containers (keeps volumes)"
	@echo "  make test-restart  test-down + test-up"
	@echo "  make test-logs     Tail logs from all services"
	@echo "  make test-status   Show container status"
	@echo "  make test-shell    Open an sftpflow CLI session via the bridge"
	@echo "  make test-ping     Send a single Ping RPC through the bridge"
	@echo "  make test-clean    test-down + delete named volumes (destructive)"
	@echo ""
	@echo "Cluster integration test (M12, 3-node multi-process env):"
	@echo ""
	@echo "  make cluster-build   Build the sftpflow-server image (re-uses test image)"
	@echo "  make cluster-up      Start the 3-node cluster compose env"
	@echo "  make cluster-test    Run scripts/test-cluster.sh end-to-end (init/join/failover)"
	@echo "  make cluster-status  Show container status for cluster env"
	@echo "  make cluster-logs    Tail logs from all cluster nodes"
	@echo "  make cluster-down    Stop cluster env (volumes preserved)"
	@echo "  make cluster-clean   cluster-down + delete cluster volumes (destructive)"

# ------------------------------------------------------------
# test-keygen: one-time client keypair generation
# ------------------------------------------------------------
# Idempotent: if the private key already exists, leave it alone.
# The public-key copy under $(PUB_KEY_DIR) is always (re)freshed so
# that regenerating the private key propagates without manual steps.
$(PRIV_KEY): | $(PRIV_KEY_DIR)
	@echo "==> generating test SSH keypair at $(PRIV_KEY)"
	@ssh-keygen -t ed25519 -f $(PRIV_KEY) -N "" -C "sftpflow-test-client"
	@chmod 600 $(PRIV_KEY)

$(PRIV_KEY_DIR):
	@mkdir -p $(PRIV_KEY_DIR)
	@chmod 700 $(PRIV_KEY_DIR)

$(PUB_KEY_DIR):
	@mkdir -p $(PUB_KEY_DIR)

# Copy the public key from the WSL-native path into the repo tree
# where docker compose's bind-mount can reach it. Refreshed on every
# test-up so rekeying is a one-step operation.
$(PUB_KEY): $(PRIV_KEY) | $(PUB_KEY_DIR)
	@cp $(PRIV_KEY_PUB) $(PUB_KEY)

test-keygen: $(PUB_KEY)
	@echo "test keypair ready: $(PRIV_KEY)"
	@echo "public key mounted into container from: $(PUB_KEY)"

# ------------------------------------------------------------
# test-build: build the sftpflow-server image
# ------------------------------------------------------------
# Kept separate from test-up so the user can see build errors
# without any "why didn't my container start?" confusion.
test-build:
	@echo "==> building sftpflow-server image"
	$(COMPOSE) -f $(COMPOSE_FILE) build sftpflow-server

# ------------------------------------------------------------
# test-up: bring everything up in the background
# ------------------------------------------------------------
# Depends on $(PUB_KEY) so first-time users get guided through the
# keygen step automatically.
test-up: $(PUB_KEY)
	@echo "==> starting sftpflow test environment"
	$(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo ""
	@echo "SSH into the daemon bridge:"
	@echo "    ssh -i $(PRIV_KEY) -p $(SFTPFLOW_SSH_PORT) sftpflow@localhost"
	@echo "MailHog UI:   http://localhost:8025"
	@echo "SFTP peers:   localhost:2201 (peer-a), localhost:2202 (peer-b)"
	@echo "              username=testuser password=testpass"

# ------------------------------------------------------------
# test-down: stop everything (keep volumes so config persists)
# ------------------------------------------------------------
test-down:
	@echo "==> stopping sftpflow test environment"
	$(COMPOSE) -f $(COMPOSE_FILE) down

test-restart: test-down test-up

# ------------------------------------------------------------
# test-logs / test-status — diagnostics
# ------------------------------------------------------------
test-logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f --tail=100

test-status:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

# ------------------------------------------------------------
# test-shell: connect through the bridge using the test key
# ------------------------------------------------------------
# -T disables pty allocation (the bridge just pipes bytes; a pty
# would muddle the NDJSON framing). StrictHostKeyChecking=accept-new
# is the right default for a disposable test env — the host keys
# are persisted in a volume, so accept-once is enough.
test-shell: $(PUB_KEY)
	ssh -T \
	    -i $(PRIV_KEY) \
	    -p $(SFTPFLOW_SSH_PORT) \
	    -o StrictHostKeyChecking=accept-new \
	    -o UserKnownHostsFile=$(PRIV_KEY_DIR)/known_hosts \
	    sftpflow@localhost

# ------------------------------------------------------------
# test-ping: fire one Ping RPC and print the reply
# ------------------------------------------------------------
# Smoke test for the full path: ssh auth -> ForceCommand -> bridge
# -> unix socket -> sftpflowd -> NDJSON reply -> stdout.
test-ping: $(PUB_KEY)
	@echo '{"id":1,"method":"ping","params":null}' | \
	    ssh -T \
	        -i $(PRIV_KEY) \
	        -p $(SFTPFLOW_SSH_PORT) \
	        -o StrictHostKeyChecking=accept-new \
	        -o UserKnownHostsFile=$(PRIV_KEY_DIR)/known_hosts \
	        sftpflow@localhost

# ------------------------------------------------------------
# test-clean: nuke volumes too. Destructive — config is gone.
# ------------------------------------------------------------
# Useful when changing the Dockerfile's uid/gid or wanting a fresh
# sshd host key fingerprint.
test-clean:
	@echo "==> tearing down + deleting named volumes"
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

# ============================================================
# Cluster integration test (M12 — 3-node multi-process env)
# ============================================================
#
# The cluster env is independent of the single-node test env: own
# compose file, own network, own volumes, but reuses the same
# Dockerfile and the same client SSH keypair. Run `make test-keygen`
# once before `make cluster-up`.
#
# Typical workflow for M12 PR-B verification:
#   make test-keygen
#   make cluster-test     # builds, brings up, runs full scenario
#   make cluster-down     # tear down when satisfied

cluster-build:
	@echo "==> building sftpflow-server image for cluster env"
	$(COMPOSE) -f $(CLUSTER_COMPOSE_FILE) build

cluster-up: $(PUB_KEY)
	@echo "==> starting sftpflow cluster test environment (3 nodes)"
	$(COMPOSE) -f $(CLUSTER_COMPOSE_FILE) up -d
	@echo ""
	@echo "Cluster is up but unbootstrapped — node.json is absent on every node."
	@echo "Bootstrap with: make cluster-test"
	@echo "Or manually:    docker exec -d sftpflow-cluster-1 sftpflowd init ..."
	@echo ""
	@echo "SSH ports: 2231 (node 1), 2232 (node 2), 2233 (node 3)"

cluster-down:
	@echo "==> stopping sftpflow cluster test environment"
	$(COMPOSE) -f $(CLUSTER_COMPOSE_FILE) down

cluster-clean:
	@echo "==> tearing down cluster + deleting volumes (destructive)"
	$(COMPOSE) -f $(CLUSTER_COMPOSE_FILE) down -v

cluster-logs:
	$(COMPOSE) -f $(CLUSTER_COMPOSE_FILE) logs -f --tail=100

cluster-status:
	$(COMPOSE) -f $(CLUSTER_COMPOSE_FILE) ps

# ------------------------------------------------------------
# cluster-test: run the full M12 acceptance scenario
# ------------------------------------------------------------
# Drives scripts/test-cluster.sh: init node 1, mint token, join 2/3,
# verify membership, kill the leader, verify re-election, restart
# the killed node, verify rejoin. Exits 0 on success, 1 on any
# verification failure (with a diagnostic dump).
cluster-test: $(PUB_KEY)
	@bash scripts/test-cluster.sh
