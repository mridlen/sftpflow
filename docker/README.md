# SFTPflow test environment (docker/)

Integration test scaffolding for milestone 6. Run it from WSL2 on
Windows (or any Linux host with Docker).

## Services

| Service          | Image                 | Host port        | Role                                |
|------------------|-----------------------|------------------|-------------------------------------|
| sftpflow-server  | built from Dockerfile | `2222` (SSH)     | `sftpflowd` + `sshd` + bridge       |
| sftp-peer-a      | `atmoz/sftp:alpine`   | `2201`           | remote SFTP target A                |
| sftp-peer-b      | `atmoz/sftp:alpine`   | `2202`           | remote SFTP target B                |
| mailhog          | `mailhog/mailhog`     | `1025`, `8025`   | SMTP sink + web UI for future email |

The two atmoz peers accept `testuser` / `testpass` and expose
`/home/testuser/upload` as the chrooted write area.

## Quick start

```sh
make test-keygen   # one-time: client SSH keypair
make test-build    # build sftpflow-server (multi-stage Rust build, slow first time)
make test-up       # start everything
make test-ping     # smoke test: single ping RPC through the bridge
make test-shell    # open an sftpflow session via the ssh bridge
make test-down     # stop (keeps config volumes)
make test-clean    # stop + wipe volumes (config, host keys, peer data)
```

## Key storage

The private key lives in `$HOME/.sftpflow-test/id_ed25519` (WSL-native
home) because `/mnt/c` doesn't honour POSIX perms and ssh refuses
world-readable private keys. Only the public half is copied into
`docker/test-keys/` where the compose bind-mount can reach it.

## Talking to the daemon from the host CLI

Once the env is up, point the regular `sftpflow` CLI at the
containerised daemon like any other remote server:

```
sftpflow> config
sftpflow(config)# server test
sftpflow(config-server)# ssh sftpflow@localhost:2222
sftpflow(config-server)# identity-file ~/.sftpflow-test/id_ed25519
sftpflow(config-server)# commit
sftpflow# connect test
```

## Layout

- `compose.test.yml` — the compose spec
- `Dockerfile.sftpflow-server` — multi-stage: build the two binaries, ship on bookworm-slim with openssh-server
- `sshd_config` — minimal, `ForceCommand`'d to `sftpflow-shell`
- `entrypoint.sh` — generates host keys on first boot, installs the client pubkey, starts the daemon, execs sshd
- `test-keys/id_ed25519.pub` — public-half copy for the container bind mount; gitignored
