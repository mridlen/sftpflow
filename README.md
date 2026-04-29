# SFTPflow

A Rust SFTP automation tool with a Cisco IOS-style interactive shell.

SFTPflow is built as a CLI that talks to a long-running daemon (`sftpflowd`)
over an SSH-wrapped NDJSON RPC channel. The daemon owns scheduled feeds,
sealed credentials, run history, and — when started as a cluster — Raft
replication of state across nodes. Operators configure feeds the same way
they configure a router: enter a config mode, edit a pending object, and
`commit` to persist.

```
sftpflow> config
sftpflow(config-feed:nightly)# source partner-a:/outbox/*.csv
sftpflow(config-feed:nightly)# destination warehouse:/inbox/
sftpflow(config-feed:nightly)# schedule 0 2 * * *
sftpflow(config-feed:nightly)# commit
```

## Components

| Crate                  | Binary           | Role                                              |
|------------------------|------------------|---------------------------------------------------|
| `sftpflow-core`        | —                | Shared data models + YAML persistence             |
| `sftpflow-proto`       | —                | NDJSON RPC envelope + message types               |
| `sftpflow-cli`         | `sftpflow`       | Interactive shell + one-shot CLI                  |
| `sftpflowd`            | `sftpflowd`      | Daemon: scheduler, transfer engine, Raft member   |
| `sftpflow-shell`       | `sftpflow-shell` | `ForceCommand` bridge: stdin/stdout ↔ unix socket |
| `sftpflow-transport`   | —                | SFTP / FTP / FTPS / HTTP(S) + PGP transport       |
| `sftpflow-cluster`     | —                | Raft scaffolding, mTLS, join token plumbing       |

The CLI runs on an operator's laptop and dials the daemon over SSH; the
daemon runs on a Linux host (or several, when clustered).

## Features

- IOS / cmsh-style modal CLI (`exec` → `config` → `config-feed` etc.) with
  tab-completion, `?` help, `show`, `commit`/`abort`.
- SFTP, FTP, FTPS, HTTP, HTTPS transports with optional PGP encrypt /
  decrypt as a feed step.
- Sealed credential store (`age` + scrypt) so passwords and SSH keys are
  not committed to `config.yaml` — feeds reference secrets by name.
- Cron scheduling. Legacy single-node mode delegates to dkron; cluster
  mode (M14+) schedules natively on the Raft leader.
- Run history in SQLite (`show runs <feed>`) and a mutation audit log
  (`show audit`).
- Raft-based clustering (M12+) with mTLS between nodes, single-use join
  tokens, hot backup, cold restore.
- HTTP `/healthz` and `/readyz` probes for Docker / Kubernetes.

---

## Install

### From source

Requires **Rust 1.80+** (edition 2024) and a working C toolchain
(MSVC on Windows; gcc/clang on Linux). The build is pure Rust where
possible — `protoc` ships vendored, no system install needed.

#### Prerequisites

Install the latest stable Rust via [rustup](https://rustup.rs) plus a
C toolchain for your platform.

**Linux (Debian / Ubuntu):**

```sh
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

**Linux (RHEL / Fedora):**

```sh
sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

**macOS:**

```sh
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

**Windows:**

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
   and select the **"Desktop development with C++"** workload (this
   provides the MSVC linker and Windows SDK).
2. Install [Git for Windows](https://git-scm.com/download/win).
3. Install Rust via [rustup-init.exe](https://www.rust-lang.org/tools/install)
   and accept the default `stable-x86_64-pc-windows-msvc` toolchain.

After install, verify and (optionally) refresh the toolchain:

```sh
rustc --version          # should report 1.80 or newer
rustup update stable     # pull the latest stable release
```

#### Build

```sh
git clone https://github.com/mridlen/sftpflow.git
cd sftpflow
cargo build --release
```

The three binaries land in `target/release/`:

- `sftpflow`        — interactive CLI
- `sftpflowd`       — daemon
- `sftpflow-shell`  — SSH `ForceCommand` bridge

Install them onto `$PATH` however you like. A typical layout:

```sh
# On the operator workstation:
install -m 0755 target/release/sftpflow        /usr/local/bin/

# On the daemon host:
install -m 0755 target/release/sftpflowd       /usr/local/bin/
install -m 0755 target/release/sftpflow-shell  /usr/local/bin/
```

### Docker (test environment)

A docker-compose-based test environment lives under [docker/](docker/).
It builds an `sftpflow-server` image (sftpflowd + sshd + bridge) plus
two `atmoz/sftp` peers and a MailHog SMTP sink. Drive it with the
[Makefile](Makefile):

```sh
make test-keygen   # one-time: generate client SSH keypair
make test-build    # multi-stage Rust build (slow first time)
make test-up       # start daemon + 2 SFTP peers + mailhog
make test-shell    # open an sftpflow CLI session via the SSH bridge
make test-down     # stop (keeps config volumes)
```

A 3-node cluster compose env is also available:

```sh
make cluster-test  # init/join/status/failover end-to-end
```

See [docker/README.md](docker/README.md) for details.

### Setting up the daemon host (production-ish)

The CLI talks to the daemon by spawning `ssh user@host sftpflow-shell`,
so you wire the bridge in via OpenSSH:

1. **Create a system user** (`sftpflow`) on the daemon host. Give it a
   home directory and `~/.ssh/authorized_keys`.

2. **Restrict the user's shell to the bridge** by setting
   `ForceCommand` for that key:

   ```
   # ~/.ssh/authorized_keys on the daemon host
   command="/usr/local/bin/sftpflow-shell --socket unix:/var/run/sftpflow/sftpflow.sock",no-pty,no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAA... operator@laptop
   ```

3. **Run the daemon.** Recommend a systemd unit; the minimum invocation:

   ```sh
   sftpflowd \
       --socket          unix:/var/run/sftpflow/sftpflow.sock \
       --db              /var/lib/sftpflow/runs.db \
       --secrets         /var/lib/sftpflow/secrets.sealed \
       --passphrase-file /etc/sftpflow/passphrase \
       --state-dir       /var/lib/sftpflow
   ```

   Provide the master passphrase via `--passphrase-file PATH` (the file
   should be `chmod 600`) or the `SFTPFLOW_PASSPHRASE` env var.

4. **Open the health port** (`0.0.0.0:7901` by default) to your load
   balancer or container orchestrator. Use `--health-bind disabled` if
   you're co-locating multiple daemons.

For an HA setup (3 nodes, Raft), see [Cluster mode](#cluster-mode) below.

---

## Usage

### First connect

The CLI maintains a registry of named server connections under
`~/.sftpflow/config.yaml`. Add one and you're done:

```
$ sftpflow
SFTPflow v0.1.1
Type 'help' for a list of commands.

sftpflow> connection add prod operator@sftpflow.example.com
Added connection 'prod': operator@sftpflow.example.com
This is the first connection — set as active.
Run 'connect' to dial the daemon.
sftpflow> connect
Connected to sftpflowd v0.1.1 (sftpflow-1, up 312s)
sftpflow>
```

`connection list` shows all registered targets; `connect <name>`
switches between them.

For local dev against a daemon on the same box, skip the registry:

```sh
sftpflow --socket unix:/tmp/sftpflow.sock
```

### Modes and the prompt

The shell is modal. The prompt tells you where you are:

| Prompt                                | Mode             | How you got there                  |
|---------------------------------------|------------------|------------------------------------|
| `sftpflow>`                           | exec             | startup                            |
| `sftpflow(config-server)#`            | server config    | `config`                           |
| `sftpflow(config-endpoint:NAME)#`     | endpoint edit    | `create endpoint NAME` / `edit`    |
| `sftpflow(config-key:NAME)#`          | PGP key edit     | `create key NAME` / `edit`         |
| `sftpflow(config-feed:NAME)#`         | feed edit        | `create feed NAME` / `edit`        |
| `sftpflow(config-feed:NAME/nextstep)#`| next-step edit   | `nextstep` (inside a feed)         |

In every config mode: `show` previews the pending object, `commit`
persists it, `abort` discards, `exit`/`end` returns to the previous mode
without touching the daemon. Type `?` or `help` for the available verbs.

### Configuring a feed end-to-end

A *feed* moves files from a source endpoint to a destination endpoint
on a schedule, optionally with PGP encrypt/decrypt or chained
`nextstep`s.

```
sftpflow> create endpoint partner-a
sftpflow(config-endpoint:partner-a)# protocol sftp
sftpflow(config-endpoint:partner-a)# host sftp.partner-a.example
sftpflow(config-endpoint:partner-a)# username uploader
sftpflow(config-endpoint:partner-a)# password_ref partner-a-pw
sftpflow(config-endpoint:partner-a)# commit

sftpflow> create endpoint warehouse
sftpflow(config-endpoint:warehouse)# protocol sftp
sftpflow(config-endpoint:warehouse)# host warehouse.internal
sftpflow(config-endpoint:warehouse)# username sftpflow
sftpflow(config-endpoint:warehouse)# ssh_key_ref warehouse-key
sftpflow(config-endpoint:warehouse)# commit

sftpflow> secret add partner-a-pw
Value:    ********
Confirm:  ********
Stored secret 'partner-a-pw'

sftpflow> create feed nightly
sftpflow(config-feed:nightly)# source partner-a:/outbox/*.csv
sftpflow(config-feed:nightly)# destination warehouse:/inbox/
sftpflow(config-feed:nightly)# schedule 0 2 * * *
sftpflow(config-feed:nightly)# commit
```

Run it manually:

```
sftpflow> run feed nightly
```

Inspect what happened:

```
sftpflow> show runs nightly
sftpflow> show feeds
sftpflow> show feed nightly
```

### One-shot mode

Any command that works at the `sftpflow>` prompt also works on argv,
which is how dkron workers and ops scripts drive the daemon:

```sh
sftpflow show feeds
sftpflow run feed nightly
sftpflow --json show runs nightly 50
sftpflow --quiet cluster status
```

Global flags:

- `--socket ADDR`   — direct-connect to a unix or TCP socket (dev mode)
- `--json`          — emit machine-readable JSON instead of human text
- `--quiet` / `-q`  — suppress banners; only result lines

### Sealed credentials

Plaintext `password` / `ssh_key` fields in `config.yaml` still work for
local dev. For anything you'd commit, use `_ref` fields and store the
real value in the sealed credential store on the daemon:

```
sftpflow> secret add partner-a-pw
sftpflow> secret list
sftpflow> secret delete partner-a-pw --dry-run
```

The store is `age`-encrypted with the daemon's master passphrase. Values
flow CLI → daemon at `secret add` time and are never read back over the
wire — the daemon resolves `*_ref` → plaintext only inside `run_feed`.

### `--dry-run` on destructive commands

`delete`, `rename`, `secret delete`, and `cluster remove` all accept
`--dry-run` (or `-n`) anywhere in their arguments. The daemon returns a
report of what *would* happen — affected files, references that would
be rewritten, warnings — without touching state. Use it to preview a
rename across a large feed set before committing.

```
sftpflow> rename --dry-run endpoint partner-a partner-a-prod
```

### Cluster mode

Cluster mode is opt-in: a daemon becomes a cluster member only after
you run `sftpflowd init` (bootstrap) or `sftpflowd join` (additional
node) and a `node.json` lands on disk. Without it, `sftpflowd run`
falls back to legacy single-node mode.

Bootstrap node 1:

```sh
sftpflowd init \
    --node-id        1 \
    --bind           0.0.0.0:7900 \
    --advertise      sftpflow-1.internal:7900 \
    --passphrase-file /etc/sftpflow/passphrase
```

Mint a join token from the CLI on node 1:

```
sftpflow> cluster token
Token: t_2f...   (expires in 1h)
Cluster CA: -----BEGIN CERTIFICATE-----
...
```

On node 2 / 3, copy the CA cert out-of-band and:

```sh
sftpflowd join sftpflow-1.internal:7900 \
    --token         t_2f... \
    --ca-cert-file  /etc/sftpflow/ca.crt \
    --bind          0.0.0.0:7900 \
    --advertise     sftpflow-2.internal:7900
```

Inspect the cluster from any node's CLI:

```
sftpflow> cluster status
sftpflow> show audit 50
```

The interactive `cluster bootstrap` and `cluster join` wizards
ssh-drive the same flows on a fresh host if you'd rather not run
`sftpflowd` directly.

### Backup and restore

On the connected node:

```
sftpflow> cluster backup /backups/sftpflow-$(date +%F).tar.gz
```

The archive contains `config.yaml`, the sealed secrets file, run
history, the audit log, and the cluster state directory. Restore
into an *empty* state on a fresh host:

```sh
sftpflowd restore /backups/sftpflow-2026-04-29.tar.gz
sftpflowd run                                  # bring the node back up
```

`restore` refuses to clobber an existing state directory.

---

## Configuration files

| Path                                      | Owner          | Purpose                              |
|-------------------------------------------|----------------|--------------------------------------|
| `~/.sftpflow/config.yaml`                 | CLI            | Connection registry, active server   |
| `~/.sftpflow_history`                     | CLI            | Readline history                     |
| `/var/lib/sftpflow/config.yaml`           | daemon         | Endpoints, keys, feeds (replicated)  |
| `/var/lib/sftpflow/secrets.sealed`        | daemon         | `age`-encrypted credential store     |
| `/var/lib/sftpflow/runs.db`               | daemon         | SQLite run history                   |
| `/var/lib/sftpflow/audit.db`              | daemon         | SQLite mutation audit log            |
| `/var/lib/sftpflow/node.json`             | daemon         | Cluster identity (cluster mode)      |
| `/var/lib/sftpflow/cluster/`              | daemon         | CA + leaf certs, Raft state          |

On Windows the default daemon state directory is `%APPDATA%\sftpflow`.
On Linux it's `/var/lib/sftpflow`. Override with `--state-dir`,
`--db`, `--secrets`, `--socket`.

## Logging

Both binaries use `env_logger`. Set `RUST_LOG=info` (or `debug`) to
turn on output:

```sh
RUST_LOG=info sftpflowd ...
RUST_LOG=debug sftpflow show feeds
```

## Health probes

The daemon serves two HTTP endpoints (default `0.0.0.0:7901`):

- `GET /healthz` — liveness (always 200 if the process is up)
- `GET /readyz`  — readiness (200 once the NDJSON server is listening
  and, in cluster mode, Raft has joined a quorum)

Pass `--health-bind disabled` to skip the listener.

---

## License

MIT. See [Cargo.toml](Cargo.toml) for the canonical metadata.
