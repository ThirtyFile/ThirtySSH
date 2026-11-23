#!/usr/bin/env python3
"""Run ThirtySSH's client test against a disposable Linux OpenSSH daemon."""
import argparse
import base64
import grp
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
KEY_TYPES = (
    ("rsa", 2048, "aes256-ctr"),
    ("ecdsa", 256, "aes128-cbc"),
    ("ecdsa", 384, "aes256-gcm@openssh.com"),
    ("ecdsa", 521, "chacha20-poly1305@openssh.com"),
)
FIXTURE_PASSPHRASE = "isolated-sshd-key-fixture"
# RFC 8032 §7.1. The Rust test uses the corresponding public test seed.
FIXTURE_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)


def ssh_string(data):
    return struct.pack(">I", len(data)) + data


def launch_command(args, work):
    if args.image is None:
        binary = args.sshd or shutil.which("sshd") or "/usr/sbin/sshd"
        return [str(Path(binary).resolve())]

    image = args.image.resolve()
    binary = image / "usr/sbin/sshd"
    helpers = image / "usr/lib/openssh"
    if not binary.is_file():
        raise ValueError("the extracted image must contain usr/sbin/sshd")

    sandbox = [
        "bwrap", "--die-with-parent", "--unshare-pid",
        "--ro-bind", "/", "/", "--dev", "/dev",
        "--proc", "/proc", "--bind", str(work), str(work),
    ]
    if (helpers / "sshd-session").is_file():
        # OpenSSH 9.8 and later run helpers from absolute paths. Overlay the
        # extracted files in the private mount namespace without installing
        # the package. Earlier releases have no separate helpers.
        sandbox.extend(("--ro-bind", str(helpers), "/usr/lib/openssh"))
    for cap in ("CAP_SETUID", "CAP_SETGID", "CAP_SYS_CHROOT", "CAP_CHOWN", "CAP_DAC_OVERRIDE"):
        sandbox.extend(("--cap-add", cap))
    if os.geteuid() != 0:
        # A rootless user namespace may map only the caller's primary GID.
        # Let sshd use its owner-only (0600) fallback on the private devpts.
        group = work / "group"
        entries = Path("/etc/group").read_bytes().splitlines(keepends=True)
        group.write_bytes(b"".join(entry for entry in entries if not entry.startswith(b"tty:")))
        sandbox.extend(("--ro-bind", str(group), "/etc/group"))
    try:
        pwd.getpwnam("sshd")
    except KeyError:
        nobody = pwd.getpwnam("nobody")
        passwd = work / "passwd"
        original = Path("/etc/passwd").read_text().rstrip("\n")
        passwd.write_text(
            f"{original}\nsshd:x:{nobody.pw_uid}:{nobody.pw_gid}:"
            "OpenSSH fixture:/run/sshd:/usr/sbin/nologin\n"
        )
        sandbox.extend(("--ro-bind", str(passwd), "/etc/passwd"))
    libraries = ":".join(str(path) for path in sorted((image / "usr/lib").glob("*-linux-gnu")))
    sandbox.extend(("--setenv", "LD_LIBRARY_PATH", libraries))
    return sandbox + [str(binary)]


def prepare(work, user):
    work.chmod(0o755)
    host_key = work / "host_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host_key], check=True)
    host_keys = work / "host_keys"
    host_keys.mkdir(mode=0o755)
    host_ca = work / "host_ca"
    subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", host_ca], check=True)
    host_identities = [host_key]
    blob = ssh_string(b"ssh-ed25519") + ssh_string(FIXTURE_PUBLIC)
    entries = [f"restrict,pty ssh-ed25519 {base64.b64encode(blob).decode()} thirtyssh-test\n"]
    identities = work / "identities"
    identities.mkdir(mode=0o700)
    user_ca = work / "user_ca"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", user_ca], check=True)
    user_public_keys = [identities / "ed25519.pub"]
    user_public_keys[0].write_text(f"ssh-ed25519 {base64.b64encode(blob).decode()} thirtyssh-test\n")
    account = pwd.getpwnam(user)
    for algorithm, bits, cipher in KEY_TYPES:
        host_identity = host_keys / f"{algorithm}_{bits}"
        subprocess.run(["ssh-keygen", "-q", "-t", algorithm, "-b", str(bits), "-N", "", "-f", host_identity], check=True)
        host_identities.append(host_identity)
        identity = identities / f"{algorithm}_{bits}"
        subprocess.run([
            "ssh-keygen", "-q", "-t", algorithm, "-b", str(bits),
            "-Z", cipher, "-a", "2", "-N", FIXTURE_PASSPHRASE, "-f", identity,
        ], check=True)
        public = identity.with_suffix(".pub")
        user_public_keys.append(public)
        entries.append(f"restrict {public.read_text()}")
        if os.geteuid() != account.pw_uid:
            os.chown(identity, account.pw_uid, account.pw_gid)
    for public in user_public_keys:
        subprocess.run(["ssh-keygen", "-q", "-s", user_ca, "-I", "fixture-user", "-n", user,
                        "-V", "-1m:+15m", public], check=True)
    if os.geteuid() != account.pw_uid:
        os.chown(identities, account.pw_uid, account.pw_gid)
    authorized = work / "authorized_keys"
    authorized.write_text("".join(entries))
    authorized.chmod(0o644)

    host_key_lines = []
    for identity in host_identities:
        subprocess.run(["ssh-keygen", "-q", "-s", host_ca, "-I", "fixture", "-h", "-n", "thirtyssh-test",
                        "-V", "-1m:+15m", identity.with_suffix(".pub")], check=True)
        host_key_lines.extend((f'HostKey "{identity}"', f'HostCertificate "{identity}-cert.pub"'))

    command = work / "fixture.sh"
    command.write_text("""#!/bin/sh
case "$SSH_ORIGINAL_COMMAND" in
  "cat; printf 'fixture stderr' >&2; exit 37")
    cat
    printf 'fixture stderr' >&2
    exit 37
    ;;
  'kill -TERM $$') kill -TERM "$$" ;;
  'pty-owner') test -t 0 && exec stat -Lc '%u:%g:%a' /proc/self/fd/0 ;;
  '')
    test -t 0 && test -t 1 || exit 1
    printf '%s/%s\n' "$TERM" "$THIRTYSSH_FIXTURE"
    stty size
    trap 'printf "interrupted\n"; exit 43' INT
    while IFS= read -r line; do
      case "$line" in
        size) stty size ;;
        ping) printf 'pong\n' ;;
        interrupt)
          printf 'ready\n'
          IFS= read -r line
          ;;
        *) exit 1 ;;
      esac
    done
    exit 0
    ;;
esac
exit 1
""")
    command.chmod(0o755)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = work / "sshd_config"
    host_keys_config = "\n".join(host_key_lines)
    config.write_text(f"""Port {port}
ListenAddress 127.0.0.1
MaxStartups 32:30:64
{host_keys_config}
PidFile "{work / 'sshd.pid'}"
AuthorizedKeysFile "{authorized}"
TrustedUserCAKeys "{user_ca}.pub"
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
AllowUsers {user}
DisableForwarding yes
PubkeyAuthentication yes
HostKeyAlgorithms +ssh-rsa,ssh-rsa-cert-v01@openssh.com
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-rsa-cert-v01@openssh.com
KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
Ciphers +aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc
MACs +hmac-sha1,hmac-sha1-etm@openssh.com
AcceptEnv THIRTYSSH_FIXTURE
ForceCommand /bin/sh "{command}"
""")
    host_blob = host_key.with_suffix(".pub").read_text().split()[1]
    return config, port, host_blob


def wait_until_listening(daemon, port):
    for _ in range(50):
        if daemon.poll() is not None:
            raise RuntimeError("sshd exited during startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("sshd did not listen on its fixture port")


def offered_kex(command, config):
    """Key exchange names in the daemon's effective configuration."""
    settings = subprocess.run(
        [*command, "-T", "-f", str(config)], capture_output=True, text=True, check=True,
    ).stdout
    for line in settings.splitlines():
        name, _, value = line.partition(" ")
        if name == "kexalgorithms":
            return value
    raise RuntimeError("sshd did not report its key exchange algorithms")


def run_test(args, port, host_blob, work, kex):
    command = [args.cargo]
    if args.toolchain:
        command.append(f"+{args.toolchain}")
    command.extend(("test", "--locked", "--manifest-path", str(ROOT / "Cargo.toml")))
    if args.offline:
        command.append("--offline")
    if args.target_dir:
        command.extend(("--target-dir", str(args.target_dir.resolve())))
    if args.des:
        command.extend(("--features", "des"))
    command.extend(("--test", "openssh_server", "--", "--ignored"))
    account = pwd.getpwnam(args.user)
    tty_gid = None
    if args.image is None or os.geteuid() == 0:
        try:
            tty_gid = grp.getgrnam("tty").gr_gid
        except KeyError:
            pass
    pty_group_mode = f"{tty_gid}:620" if tty_gid is not None else f"{account.pw_gid}:600"
    environment = {
        "THIRTYSSH_TEST_SSHD_PORT": str(port),
        "THIRTYSSH_TEST_SSHD_HOST_KEY": host_blob,
        "THIRTYSSH_TEST_SSHD_USER": args.user,
        "THIRTYSSH_TEST_SSHD_KEX": kex,
        "THIRTYSSH_TEST_SSHD_PTY_OWNER": f"{account.pw_uid}:{pty_group_mode}",
        "THIRTYSSH_TEST_SSHD_IDENTITIES": str(work / "identities"),
        "THIRTYSSH_TEST_SSHD_KEY_PASSPHRASE": FIXTURE_PASSPHRASE,
        "THIRTYSSH_TEST_SSHD_HOST_KEYS": str(work / "host_keys"),
        "THIRTYSSH_TEST_SSHD_HOST_CA": str(work / "host_ca.pub"),
    }
    if os.geteuid() != account.pw_uid:
        command = ["runuser", "-u", args.user, "--", "env",
                   *(f"{key}={value}" for key, value in environment.items()), *command]
    subprocess.run(command, env=os.environ | environment, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--sshd", help="path to an installed Linux sshd")
    source.add_argument("--image", type=Path, help="directory holding an extracted openssh-server package")
    parser.add_argument("--user", required=True, help="local non-root account with a shell")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--toolchain")
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--des", action="store_true", help="test 3des-cbc in the ThirtySSH client")
    args = parser.parse_args()
    account = pwd.getpwnam(args.user)
    if account.pw_uid == 0 or any(char in args.user for char in " \t\r\n*?,!@#"):
        parser.error("--user must name a single non-root account")

    with tempfile.TemporaryDirectory(prefix="thirtyssh-sshd-") as temporary:
        work = Path(temporary)
        config, port, host_blob = prepare(work, args.user)
        command = launch_command(args, work)
        kex = offered_kex(command, config)
        log_path = work / "sshd.log"
        with log_path.open("w") as log:
            daemon = subprocess.Popen(
                [*command, "-D", "-e", "-f", str(config)], stdout=log, stderr=log,
            )
            try:
                wait_until_listening(daemon, port)
                run_test(args, port, host_blob, work, kex)
            except (RuntimeError, subprocess.CalledProcessError):
                print(log_path.read_text())
                raise
            finally:
                if daemon.poll() is None:
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait()


if __name__ == "__main__":
    main()
