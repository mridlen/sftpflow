#!/usr/bin/env python3
# ============================================================
# scripts/drive-cli-validate-join.py - pty driver for live-validating
#                                       the CLI's `cluster join`
# ============================================================
#
# Spawns the sftpflow CLI in a pseudo-TTY (rustyline refuses to
# read from a pipe), waits for prompts, and types the validation
# script:
#     cluster status
#     cluster join sftpflow@localhost:2234
#     cluster status
#     exit
#
# Streams the CLI's output back to stdout so the operator can see
# what happened. Returns 0 if the cluster size grew from 3 to 4,
# 1 otherwise.

import os, pty, sys, select, time, re

CLI = "/tmp/sftpflow-target/release/sftpflow"

PROMPT = re.compile(rb"sftpflow(?:\([^)]+\))?[#>]\s*$")

def expect_prompt(fd, buf, timeout=60):
    """Read from fd until the prompt regex matches at end of buf, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1.0)
        if fd in ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                return buf, False
            if not chunk:
                return buf, False
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            buf += chunk
            # match against the last few hundred bytes only
            tail = buf[-512:].rstrip(b"\x1b[0m").rstrip()
            if PROMPT.search(tail):
                return buf, True
    return buf, False

def send(fd, line):
    sys.stdout.buffer.write(b"<<< " + line.encode() + b"\n")
    sys.stdout.buffer.flush()
    os.write(fd, (line + "\n").encode())

def main():
    pid, fd = pty.fork()
    if pid == 0:
        env = os.environ.copy()
        env["SFTPFLOW_PASSPHRASE"] = "cluster-test-passphrase"
        # Replace child with the CLI
        os.execvpe(CLI, [CLI], env)
        os._exit(127)

    buf = b""
    # initial banner + first prompt
    buf, ok = expect_prompt(fd, buf, timeout=30)
    if not ok:
        print("\n[driver] never saw initial prompt", file=sys.stderr)
        os.kill(pid, 9); os.waitpid(pid, 0)
        sys.exit(1)

    # Probe initial cluster state
    send(fd, "cluster status")
    buf_before = buf
    buf, ok = expect_prompt(fd, buf, timeout=30)
    if not ok:
        print("\n[driver] never returned to prompt after first 'cluster status'", file=sys.stderr)
        os.kill(pid, 9); os.waitpid(pid, 0); sys.exit(1)
    initial_excerpt = buf[len(buf_before):]
    initial_count = len(re.findall(rb"^\s+\d+\s+(?:leader|voter|learner)\s",
                                    initial_excerpt, re.MULTILINE))
    print(f"\n[driver] initial member count parsed from output: {initial_count}", file=sys.stderr)

    # Run the new join command
    send(fd, "cluster join sftpflow@localhost:2234")
    buf, ok = expect_prompt(fd, buf, timeout=120)
    if not ok:
        print("\n[driver] never returned to prompt after 'cluster join'", file=sys.stderr)
        os.kill(pid, 9); os.waitpid(pid, 0); sys.exit(1)

    # Final state probe
    send(fd, "cluster status")
    buf_before = buf
    buf, ok = expect_prompt(fd, buf, timeout=30)
    if not ok:
        print("\n[driver] never returned to prompt after final 'cluster status'", file=sys.stderr)
        os.kill(pid, 9); os.waitpid(pid, 0); sys.exit(1)
    final_excerpt = buf[len(buf_before):]
    final_count = len(re.findall(rb"^\s+\d+\s+(?:leader|voter|learner)\s",
                                  final_excerpt, re.MULTILINE))
    print(f"\n[driver] final member count parsed from output: {final_count}", file=sys.stderr)

    send(fd, "exit")
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass

    if final_count > initial_count:
        print(f"\n[driver] PASS: cluster grew {initial_count} -> {final_count}", file=sys.stderr)
        sys.exit(0)
    else:
        print(f"\n[driver] FAIL: cluster did not grow ({initial_count} -> {final_count})", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
