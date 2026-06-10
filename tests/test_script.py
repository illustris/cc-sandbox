import shlex

SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=2"


def as_user(cmd):
    return "su - testuser -c " + shlex.quote(cmd)


def probe(name, ip):
    remote = f"timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/9000'"
    name_arg = f"--name {name} " if name else ""
    return as_user(f"cogbox ssh {name_arg}{shlex.quote(remote)}")


def boot_and_wait(unit, args, ssh_port):
    # `cogbox start --no-ssh` daemonizes the VM (passt + QEMU) itself and
    # returns once QEMU has come up, WITHOUT opening an interactive SSH session
    # (which would block this command forever). The auto-ssh default is covered
    # separately in Phase J. The daemon is setsid'd into its own session, so it
    # survives this command and is torn down later by `cogbox stop`. The `unit`
    # arg is kept for call-site compatibility but is now unused.
    _ = unit
    machine.succeed(as_user(f"cogbox start --no-ssh {args}".strip()))
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p {ssh_port} root@127.0.0.1 true"),
        timeout=600,
    )


def stop_instance(unit, name=None):
    # `cogbox stop` SIGTERMs the daemon; its trap forwards to QEMU + passt
    # and the EXIT trap removes the runtime dir. This exercises the
    # stop-reliability path that the background-by-default model depends on.
    _ = unit
    name_arg = f"--name {name}" if name else ""
    machine.succeed(as_user(f"cogbox stop {name_arg}".strip()))
    runtime = "/run/user/1000/cogbox" + (("-" + name) if name else "")
    machine.wait_until_fails(f"test -e {runtime}/pid", timeout=30)


machine.wait_for_unit("multi-user.target")

# Pre-create testuser ssh keypair
machine.succeed(as_user('ssh-keygen -t ed25519 -N "" -f /home/testuser/.ssh/id_ed25519'))

# Set up fake outbound targets and a single TCP listener.
# Inner VM connects to 10.99.0.{1,2}:9000; passt issues the same connect
# on the outer VM, which routes locally to the listener bound on 0.0.0.0.
machine.succeed("ip addr add 10.99.0.1/32 dev lo")
machine.succeed("ip addr add 10.99.0.2/32 dev lo")
machine.succeed("systemd-run --unit=test-listener --collect nc -l -k -p 9000")
machine.wait_for_open_port(9000)

with subtest("Phase A: CLI / state without booting"):
    # A1: first-run init for the default instance, network=none.
    # A non-interactive stdin auto-selects all harnesses, so claude-code,
    # opencode, and codex host paths are all seeded.
    machine.succeed(as_user("cogbox init -y --network none"))
    machine.succeed("test -f /home/testuser/.config/cogbox/instances/default/config.json")
    machine.succeed("test -f /home/testuser/.config/cogbox/authorized_keys")
    machine.succeed("test -d /home/testuser/.local/share/cogbox/instances/default")
    machine.succeed("test -f /home/testuser/.claude.json")
    machine.succeed("test -d /home/testuser/.claude")
    machine.succeed("test -d /home/testuser/.config/opencode")
    machine.succeed("test -d /home/testuser/.local/share/opencode")
    machine.succeed("test -d /home/testuser/.codex")
    machine.succeed(
        "test -f /home/testuser/.local/share/cogbox/instances/default/.config/active-harnesses"
    )
    active = machine.succeed(
        "cat /home/testuser/.local/share/cogbox/instances/default/.config/active-harnesses"
    ).strip().splitlines()
    assert "claude-code" in active and "opencode" in active and "codex" in active, active
    # Old top-level default config must NOT be created any more.
    machine.fail("test -e /home/testuser/.config/cogbox/config.json")
    net = machine.succeed(
        "jq -r .network /home/testuser/.config/cogbox/instances/default/config.json"
    ).strip()
    assert net == "none", f"expected network=none, got {net!r}"

    # A2: list shows the default instance
    out = machine.succeed(as_user("cogbox list"))
    assert "(default)" in out, out
    assert "ssh:2222" in out, out
    assert "net:none" in out, out

    # A3: named instance with rules mode -> auto-assigned ports
    machine.succeed(as_user("cogbox init -y --name work --network rules"))
    # Named instance data must be a sibling of the default's data dir, not
    # nested inside it. A default-instance boot 9p-shares its data dir into
    # the guest; if named instances live under it, they leak across.
    machine.succeed("test -d /home/testuser/.local/share/cogbox/instances/work")
    machine.fail("test -e /home/testuser/.local/share/cogbox/instances/default/instances")
    ssh_port = machine.succeed(
        "jq -r .sshPort /home/testuser/.config/cogbox/instances/work/config.json"
    ).strip()
    assert ssh_port == "2223", f"expected auto-assigned 2223, got {ssh_port!r}"
    net_kind = machine.succeed(
        "jq -r '.network | type' /home/testuser/.config/cogbox/instances/work/config.json"
    ).strip()
    assert net_kind == "object", f"expected rules object, got {net_kind!r}"

    # A4: list shows both
    out = machine.succeed(as_user("cogbox list"))
    assert "(default)" in out and "work" in out, out

    # A5: rules add / list / del on the work instance.
    # Use --at to land the new rules at known positions; otherwise they
    # append after the seeded bogon-deny ruleset and del 1 would remove
    # a seeded rule instead of the test rule. Use 8.8.8.8/32 instead of
    # 0.0.0.0/0 for the second rule so its substring check doesn't
    # collide with the seeded `allow 0.0.0.0/0`.
    machine.succeed(as_user("cogbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    machine.succeed(as_user("cogbox rules add deny 8.8.8.8/32 --at 2 --name work"))
    out = machine.succeed(as_user("cogbox rules list --name work"))
    assert "10.99.0.1/32" in out and "8.8.8.8/32" in out, out
    machine.succeed(as_user("cogbox rules del 1 --name work"))
    out = machine.succeed(as_user("cogbox rules list --name work"))
    assert "10.99.0.1/32" not in out and "8.8.8.8/32" in out, out

    # A6: rules add fails on a non-rules instance (default is network=none)
    machine.fail(as_user("cogbox rules add allow 1.1.1.1/32"))

# Install host pubkey for inner-VM SSH (shared by the default and work instances)
machine.succeed(
    "cp /home/testuser/.ssh/id_ed25519.pub "
    "/home/testuser/.config/cogbox/authorized_keys"
)

with subtest("Phase B: --network none blocks all outbound"):
    boot_and_wait("cc-default", "", ssh_port=2222)
    out = machine.succeed(as_user("cogbox list"))
    assert "(running)" in out, out
    hostname = machine.succeed(as_user("cogbox ssh hostname")).strip()
    assert hostname == "cogbox-default", f"unexpected inner hostname {hostname!r}"
    machine.fail(probe(None, "10.99.0.1"))
    machine.fail(probe(None, "10.99.0.2"))
    stop_instance("cc-default")

with subtest("Phase C: --network full allows outbound"):
    # Reinit the default instance in full mode
    machine.succeed("rm -f /home/testuser/.config/cogbox/instances/default/config.json")
    machine.succeed(as_user("cogbox init -y --network full"))
    machine.succeed(
        "cp /home/testuser/.ssh/id_ed25519.pub "
        "/home/testuser/.config/cogbox/authorized_keys"
    )
    boot_and_wait("cc-default", "", ssh_port=2222)
    machine.succeed(probe(None, "10.99.0.1"))
    machine.succeed(probe(None, "10.99.0.2"))
    stop_instance("cc-default")

with subtest("Phase D: --network rules with dynamic reload"):
    # work instance carries the seeded bogon-deny ruleset; 10.99.0.0/8
    # falls inside `deny 10.0.0.0/8`, so we need an explicit allow at the
    # front for 10.99.0.1/32 to be reachable.
    machine.succeed(as_user("cogbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    # Initial policy: .1 allowed, .2 denied
    machine.succeed(probe("work", "10.99.0.1"))
    machine.fail(probe("work", "10.99.0.2"))

    # Dynamic add: insert allow 10.99.0.2/32 BEFORE the catch-all deny
    out = machine.succeed(as_user("cogbox rules add allow 10.99.0.2/32 --at 2 --name work"))
    assert "Rules reloaded" in out, out
    machine.succeed(probe("work", "10.99.0.2"))

    # Dynamic delete: drop the .1 allow at position 1
    out = machine.succeed(as_user("cogbox rules del 1 --name work"))
    assert "Rules reloaded" in out, out
    machine.fail(probe("work", "10.99.0.1"))
    machine.succeed(probe("work", "10.99.0.2"))

    stop_instance("cc-work", name="work")

with subtest("Phase E: per-instance flake adds package + nix DB registers it"):
    flake_path = "/home/testuser/.config/cogbox/instances/default/flake/flake.nix"

    # Earlier phases left a scaffolded no-op flake.nix; confirm and rewrite
    # to a flake that adds pkgs.hello via both systemPackages and
    # extraDependencies. No `inputs.nixpkgs` so `pkgs` flows in from the
    # surrounding NixOS evaluation (cogbox's nixpkgs).
    machine.succeed(f"test -f {flake_path}")
    machine.succeed(as_user("""cat > """ + flake_path + """ <<'NIX_EOF'
{
    description = "test-ext-hello";
    outputs = { self }: {
        nixosModules.default = { pkgs, ... }: {
            environment.systemPackages = [ pkgs.hello ];
            system.extraDependencies = [ pkgs.hello ];
        };
    };
}
NIX_EOF"""))

    # Boot default (still in --network full from Phase C). The wrapper
    # detects the edited flake.nix, re-execs via nix run with the override,
    # rebuilds the microvm runner with hello in the closure.
    boot_and_wait("cc-default", "", ssh_port=2222)
    hello_path = machine.succeed(
        as_user("cogbox ssh 'readlink -f $(command -v hello)'")
    ).strip()
    assert hello_path.startswith("/nix/store/") and "hello-" in hello_path, hello_path
    # nix-store --check-validity succeeds only if the path is in the guest's
    # /nix/var/nix/db -- proving it's a registered store object, not just
    # a file dropped in via the 9p ro-store share.
    machine.succeed(
        as_user(f"cogbox ssh 'nix-store --check-validity {hello_path}'")
    )
    stop_instance("cc-default")

    # Revert to the byte-exact scaffold so the next boot skips re-exec
    # again (the wrapper compares the on-disk flake.nix to its built-in
    # scaffold and skips the re-eval when they match).
    machine.succeed(f"rm {flake_path}")
    # Re-running init repopulates the scaffold without prompting
    # since everything else exists.
    machine.succeed(as_user("cogbox init -y --network full"))
    boot_and_wait("cc-default", "", ssh_port=2222)
    machine.fail(
        as_user("cogbox ssh 'command -v hello'")
    )
    stop_instance("cc-default")

with subtest("Phase F: opencode + codex harnesses wired into the VM"):
    boot_and_wait("cc-default", "", ssh_port=2222)
    # All harness launchers are on $PATH inside the VM unconditionally
    # (D4: binaries always installed regardless of which harness has
    # active host state).
    c_path = machine.succeed(as_user("cogbox ssh 'command -v c'")).strip()
    oc_path = machine.succeed(as_user("cogbox ssh 'command -v oc'")).strip()
    cx_path = machine.succeed(as_user("cogbox ssh 'command -v cx'")).strip()
    assert c_path and oc_path and cx_path, (c_path, oc_path, cx_path)

    # Per-harness config dirs are mounted at the expected guest paths.
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.config/opencode'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.local/share/opencode'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.codex'"
    ))
    # Ephemeral paths (cache + state) bind from the harness overlay.
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.cache/opencode'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.local/state/opencode'"
    ))

    # Single-image overlay layout: claude-code/config, opencode/{config,data},
    # and codex/home all live under the shared harness-rw mount.
    machine.succeed(as_user(
        "cogbox ssh 'test -d /var/lib/harness-rw/claude-code/config/upper'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'test -d /var/lib/harness-rw/opencode/config/upper'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'test -d /var/lib/harness-rw/codex/home/upper'"
    ))

    # Persistence: write a file under opencode's config overlay, reboot,
    # verify it survives. The sync flushes the write through overlayfs
    # to the ext4 overlay image; without it, SIGTERM-killed QEMU loses
    # uncommitted journal entries.
    machine.succeed(as_user(
        "cogbox ssh 'echo persisted > /root/.config/opencode/marker && sync'"
    ))
    stop_instance("cc-default")
    boot_and_wait("cc-default", "", ssh_port=2222)
    out = machine.succeed(as_user(
        "cogbox ssh 'cat /root/.config/opencode/marker'"
    )).strip()
    assert out == "persisted", out
    stop_instance("cc-default")

with subtest("Phase I: background default, console + monitor sockets, stop teardown"):
    rt = "/run/user/1000/cogbox"

    # console/monitor on a stopped instance fail cleanly.
    rc, _ = machine.execute(as_user("cogbox console 2>&1"))
    assert rc != 0, "console on stopped instance should fail"
    rc, _ = machine.execute(as_user("cogbox monitor 2>&1"))
    assert rc != 0, "monitor on stopped instance should fail"

    # `cogbox start` daemonizes and returns; boot_and_wait asserts SSH is up.
    boot_and_wait("cc-default", "", ssh_port=2222)

    # The per-instance console + monitor sockets exist, and the serial
    # console was captured to console.log (proves the chardev rewrite took).
    machine.succeed(f"test -S {rt}/console.sock")
    machine.succeed(f"test -S {rt}/monitor.sock")
    machine.succeed(f"test -f {rt}/console.log")

    # Drive the live serial console over its socket: the guest runs an
    # autologin root shell on ttyS0, so a typed command produces output.
    console_drv = r'''
import socket, time, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/user/1000/cogbox/console.sock")
s.settimeout(1.0)
buf = b""
deadline = time.time() + 20
s.sendall(b"\n")
while time.time() < deadline:
    s.sendall(b"uname -n\n")
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    if b"cogbox-default" in buf:
        break
sys.stderr.write(repr(buf[-200:]))
sys.exit(0 if b"cogbox-default" in buf else 1)
'''
    machine.succeed("cat > /tmp/console-drv.py << 'PY_EOF'\n" + console_drv + "\nPY_EOF")
    machine.succeed(as_user("python3 /tmp/console-drv.py"))

    # Drive the HMP monitor over its socket: 'info status' reports VM state.
    monitor_drv = r'''
import socket, time, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/user/1000/cogbox/monitor.sock")
s.settimeout(1.0)
buf = b""
deadline = time.time() + 15
while time.time() < deadline:
    s.sendall(b"info status\n")
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    if b"running" in buf or b"VM status" in buf:
        break
sys.stderr.write(repr(buf[-200:]))
sys.exit(0 if (b"running" in buf or b"VM status" in buf) else 1)
'''
    machine.succeed("cat > /tmp/monitor-drv.py << 'PY_EOF'\n" + monitor_drv + "\nPY_EOF")
    machine.succeed(as_user("python3 /tmp/monitor-drv.py"))

    # Stop must tear the VM down without --force: SIGTERM to the daemon must
    # propagate to QEMU + passt (the trap), not just orphan them.
    stop_instance("cc-default")
    rc, _ = machine.execute(as_user("cogbox status"))
    assert rc == 3, f"expected stopped (exit 3) after stop, got {rc}"
    # No QEMU process should survive a plain stop. Match on the process name
    # (comm = "qemu-system-x86") NOT the full cmdline: microvm-run launches
    # QEMU via `exec -a microvm@nixos`, so the cmdline contains no "qemu" and
    # `pgrep -f qemu-system` would (a) never match the VM and (b) self-match
    # the test driver's own `bash -c 'pgrep ...'` wrapper.
    machine.wait_until_fails("pgrep qemu-system", timeout=15)

with subtest("Phase H: TCP remap routes via SOCKS5 to a host stub"):
    # The shim's remap primitive (zig/src/filter.zig::RemapRule) rewrites
    # an outbound TCP connect to a loopback target and drives a SOCKS5 v5
    # CONNECT handshake on it, carrying the original destination. The
    # downstream proxy thus learns where the guest *wanted* to go.
    #
    # This phase validates that path end-to-end:
    #   1. A Python stub on the outer VM (127.0.0.1:18080) speaks SOCKS5,
    #      records the CONNECT target to a log, replies success.
    #   2. The cogbox work instance gets a remap rule for
    #      10.99.0.1/32:9000 -> 127.0.0.1:18080 via direct config.json
    #      edit (no CLI verb for remap yet).
    #   3. The cogbox guest probes 10.99.0.1:9000; passt's connect() is
    #      intercepted by the shim, rewritten to 127.0.0.1:18080, and
    #      hands off via SOCKS5.
    #   4. The stub log must show a CONNECT for the *original* destination.

    # Raw string: backslash escapes inside the bytes literals are
    # preserved verbatim through the heredoc.
    stub_script = r'''
import socket, struct, sys
LOG = "/tmp/socks5-conn.log"
open(LOG, "w").close()
def log(s):
    with open(LOG, "a") as f:
        f.write(s + "\n")
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 18080))
srv.listen(8)
log("ready")
while True:
    c, _ = srv.accept()
    try:
        greet = c.recv(3)
        if greet != b"\x05\x01\x00":
            c.close(); continue
        c.sendall(b"\x05\x00")
        hdr = c.recv(4)
        if len(hdr) < 4 or hdr[:2] != b"\x05\x01" or hdr[3] != 1:
            c.close(); continue
        addr = c.recv(4)
        port_b = c.recv(2)
        ip_str = ".".join(str(b) for b in addr)
        port = struct.unpack(">H", port_b)[0]
        log("CONNECT {0}:{1}".format(ip_str, port))
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        # Consume any echo bytes the client sends so probe()'s bash
        # exec doesn't block on a write to a full socket buffer.
        try:
            c.recv(64)
        except Exception:
            pass
    finally:
        c.close()
'''
    machine.succeed(
        "cat > /tmp/socks5-stub.py << 'PY_EOF'\n" + stub_script + "\nPY_EOF"
    )
    machine.succeed("systemd-run --unit=socks5-stub --collect python3 /tmp/socks5-stub.py")
    # Stub writes "ready" to its log on bind+listen.
    machine.wait_until_succeeds("grep -q ready /tmp/socks5-conn.log", timeout=10)

    # Pick a target that has NO direct listener so we can prove the
    # remap is what made the probe succeed -- not a lucky catch-all on
    # the existing nc -l -p 9000 (which binds 0.0.0.0).
    machine.succeed("ip addr add 10.99.0.3/32 dev lo")
    # Port 9100: no listener anywhere on the outer VM. Without remap,
    # a TCP connect should be refused (RST).

    # Restore .1 allow (phase D ended after `del 1` which removed .1)
    # and explicitly allow .3.
    machine.succeed(as_user("cogbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    machine.succeed(as_user("cogbox rules add allow 10.99.0.3/32 --at 2 --name work"))

    # Hand-edit the remap table; no CLI verb yet.
    machine.succeed(
        "jq '.network.remap = [{\"from\":\"tcp 10.99.0.3/32:9100\",\"to\":\"tcp 127.0.0.1:18080\"}]' "
        "/home/testuser/.config/cogbox/instances/work/config.json > /tmp/work-cfg.json "
        "&& mv /tmp/work-cfg.json /home/testuser/.config/cogbox/instances/work/config.json "
        "&& chown testuser:users /home/testuser/.config/cogbox/instances/work/config.json"
    )

    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    # The launch script renders both rules and remap into one file.
    rules_text = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert "remap tcp 10.99.0.3/32:9100 -> tcp 127.0.0.1:18080" in rules_text, rules_text

    # End-to-end: guest connect to 10.99.0.3:9100 must succeed because
    # the shim rewrote the destination to the SOCKS5 stub. The direct
    # 10.99.0.3:9100 path would otherwise be refused (no listener).
    def probe_port(name, ip, port):
        remote = "timeout 3 bash -c 'exec 3<>/dev/tcp/" + ip + "/" + str(port) + "'"
        return as_user("cogbox ssh --name " + name + " " + shlex.quote(remote))

    machine.succeed(probe_port("work", "10.99.0.3", 9100))

    # The stub recorded a CONNECT for the original (pre-remap) target.
    out = machine.succeed("cat /tmp/socks5-conn.log")
    assert "CONNECT 10.99.0.3:9100" in out, "stub log was: " + repr(out)

    # Sanity: connect to 10.99.0.3 on a different port has no remap rule
    # and no listener -- must fail.
    machine.fail(probe_port("work", "10.99.0.3", 9101))

    # Dynamic add through the `cogbox remap` CLI -- the running passt
    # must pick up the new rule via SIGUSR1 reload without restart.
    # Insert at position 1 so the index of the rule we're about to test
    # is deterministic (the .3:9100 jq-edit rule already occupies a
    # slot, so a plain append would land at position 2).
    machine.succeed("ip addr add 10.99.0.4/32 dev lo")
    machine.succeed(as_user("cogbox rules add allow 10.99.0.4/32 --at 1 --name work"))
    out = machine.succeed(as_user(
        "cogbox remap add 'tcp 10.99.0.4/32:9200' 'tcp 127.0.0.1:18080' --at 1 --name work"
    ))
    assert "Rules reloaded" in out, out

    out = machine.succeed(as_user("cogbox remap list --name work"))
    # The new rule should be at index 1 after --at 1.
    first_line = out.splitlines()[0]
    assert first_line == "1: tcp 10.99.0.4/32:9200 -> tcp 127.0.0.1:18080", out

    # The reloaded rule must take effect without a VM restart.
    machine.succeed(probe_port("work", "10.99.0.4", 9200))
    out = machine.succeed("cat /tmp/socks5-conn.log")
    assert "CONNECT 10.99.0.4:9200" in out, "stub log was: " + repr(out)

    # `cogbox remap del 1` removes the .4:9200 rule we just inserted.
    # After reload, the probe must fail -- no remap, no listener.
    out = machine.succeed(as_user("cogbox remap del 1 --name work"))
    assert "Rules reloaded" in out, out
    machine.fail(probe_port("work", "10.99.0.4", 9200))

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop socks5-stub")

with subtest("Phase K: L7 vhost filtering (passthrough tier)"):
    # The L7 layer funnels ALL guest 80/443 through the host-side proxy,
    # which allows only whitelisted vhosts (by TLS SNI / HTTP Host) and
    # re-resolves the name host-side. The decisive property: allowing
    # vhost-a does NOT grant a sibling vhost-b that shares the SAME IP.
    #
    # Guest and node are different machines, so we decouple resolution --
    # which IS the security story:
    #   - guest pins names to the origin IP with curl --resolve;
    #   - the node's /etc/hosts (networking.hosts in cogbox.nix) maps the
    #     vhosts to 203.0.113.5 for the proxy's host-side re-resolution.
    # 203.0.113.0/24 (TEST-NET-3) is NOT in the proxy's SSRF floor, so a
    # legit allow can reach it; evil-meta.test -> 169.254.169.254 must be
    # refused by that floor.

    # Throwaway self-signed cert for the origin (passthrough never validates
    # it; the guest uses curl -k). Combined cert+key in one PEM.
    machine.succeed(
        "openssl req -x509 -newkey rsa:2048 -keyout /tmp/origin.key "
        "-out /tmp/origin.crt -days 1 -nodes -subj '/CN=test-origin' "
        "-addext 'subjectAltName=DNS:vhost-a.test,DNS:vhost-b.test' 2>/dev/null "
        "&& cat /tmp/origin.crt /tmp/origin.key > /tmp/origin.pem"
    )
    machine.succeed("ip addr add 203.0.113.5/32 dev lo")

    # Origin: HTTPS on :443 + HTTP on :80, both bound to 203.0.113.5. Each
    # request's Host is appended to a hit log; the proxy only ever connects
    # here for an ALLOWED vhost, so the log is the ground truth for which
    # vhosts actually reached a backend.
    origin_script = r'''
import socket, ssl, threading
ORIGIN = "203.0.113.5"
HITLOG = "/tmp/origin-hits.log"
open(HITLOG, "w").close()
lock = threading.Lock()
def loghit(s):
    with lock:
        with open(HITLOG, "a") as f:
            f.write(s + "\n")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/origin.pem")
def respond(conn, scheme):
    data = conn.recv(8192).decode("latin1")
    first = data.split("\r\n")[0]
    parts = first.split(" ")
    path = parts[1] if len(parts) > 1 else "?"
    host = ""
    for h in data.split("\r\n"):
        if h.lower().startswith("host:"):
            host = h.split(":", 1)[1].strip()
    loghit("%s host=%s path=%s" % (scheme, host, path))
    body = ("ok %s host=%s path=%s" % (scheme, host, path)).encode()
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                 % (len(body), body))
def handle_tls(raw):
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        try: raw.close()
        except Exception: pass
        return
    try:
        respond(c, "TLS")
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
def handle_http(c):
    try:
        respond(c, "HTTP")
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
def serve(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ORIGIN, port))
    s.listen(16)
    loghit("listen %d" % port)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()
threading.Thread(target=serve, args=(443, handle_tls), daemon=True).start()
serve(80, handle_http)
'''
    machine.succeed("cat > /tmp/l7-origin.py << 'PY_EOF'\n" + origin_script + "\nPY_EOF")
    machine.succeed("systemd-run --unit=l7-origin --collect python3 /tmp/l7-origin.py")
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/origin-hits.log", timeout=10)
    machine.wait_until_succeeds("grep -q 'listen 80' /tmp/origin-hits.log", timeout=10)

    # The origin IP is BLOCKED at L4 (TEST-NET deny + public catch-all). Under
    # the L7-composition model an L7 `allow` supersedes that block, so vhost-a
    # is reachable with NO L4 IP allow, while an unlisted sibling on the same
    # blocked IP is dropped. (Keeping the public catch-all also proves the SSRF
    # canary's metadata IP is stopped by the hard floor, not by an L4 deny.)
    machine.succeed(as_user(
        "printf 'deny 203.0.113.0/24\\nallow 0.0.0.0/0\\n' | cogbox rules set --name work"
    ))
    # Seed the L7 allowlist with vhost-a only (vhost-b is the sibling).
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --name work"))

    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    nf = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18443" in nf, nf
    assert "remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:18081" in nf, nf
    assert "deny udp 0.0.0.0/0:443" in nf, nf
    assert "deny tcp ::/0" in nf, nf
    l7r = machine.succeed("cat /run/user/1000/cogbox-work/l7-rules")
    assert "allow vhost-a.test" in l7r, l7r
    # The proxy must be running (its pidfile exists and the process is alive).
    machine.succeed("test -f /run/user/1000/cogbox-work/l7proxy.pid")
    machine.succeed("kill -0 $(cat /run/user/1000/cogbox-work/l7proxy.pid)")

    def gcurl(extra):
        cmd = "curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 " + extra
        return machine.execute(as_user("cogbox ssh --name work " + shlex.quote(cmd)))

    # Allowed vhost over HTTPS -> 200, even though its IP is L4-blocked
    # (proves the L7 allow supersedes the L4 deny; re-resolved + spliced E2E).
    rc, out = gcurl("--resolve vhost-a.test:443:203.0.113.5 https://vhost-a.test/p1")
    assert rc == 0 and out.strip().endswith("200"), f"vhost-a https rc={rc} out={out!r}"
    # Same vhost over plaintext HTTP :80 -> 200.
    rc, out = gcurl("--resolve vhost-a.test:80:203.0.113.5 http://vhost-a.test/p1")
    assert rc == 0 and out.strip().endswith("200"), f"vhost-a http rc={rc} out={out!r}"

    # CORE PROPERTY: sibling vhost-b on the SAME IP is blocked. Dual proof:
    #  (1) the guest request fails, and
    #  (2) the origin never logs a hit for vhost-b (it never connected).
    rc, out = gcurl("--resolve vhost-b.test:443:203.0.113.5 https://vhost-b.test/")
    assert rc != 0, f"sibling vhost-b should be blocked, got rc={rc} out={out!r}"
    hits = machine.succeed("cat /tmp/origin-hits.log")
    assert "host=vhost-a.test" in hits, hits
    assert "vhost-b.test" not in hits, f"sibling reached origin! log={hits!r}"

    # Direct-IP / no-SNI HTTPS -> denied (proxy can't identify a vhost).
    rc, out = gcurl("https://203.0.113.5/")
    assert rc != 0, f"direct-IP no-SNI should be blocked, got rc={rc}"

    # SSRF canary: an allowed name that resolves (host-side) to the cloud
    # metadata IP MUST be refused by the proxy's non-overridable SSRF floor.
    # Without the post-resolution re-check this would connect.
    machine.succeed(as_user("cogbox l7 add allow evil-meta.test --name work"))
    rc, out = gcurl("--resolve evil-meta.test:443:169.254.169.254 https://evil-meta.test/")
    assert rc != 0, f"SSRF canary should be refused, got rc={rc} out={out!r}"

    # Hot reload + renderer-drift guard: adding vhost-b flips its
    # reachability WITHOUT a VM restart, and the funnel lines survive the
    # hot re-render of netfilter-rules.
    out = machine.succeed(as_user("cogbox l7 add allow vhost-b.test --name work"))
    assert "Rules reloaded" in out, out
    nf2 = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18443" in nf2, nf2
    rc, out = gcurl("--resolve vhost-b.test:443:203.0.113.5 https://vhost-b.test/")
    assert rc == 0 and out.strip().endswith("200"), f"vhost-b should now be allowed rc={rc} out={out!r}"

    # And deleting it blocks it again (proxy SIGHUP reload).
    # vhost-b is the last rule added; list to find its index.
    listing = machine.succeed(as_user("cogbox l7 list --name work"))
    idx = None
    for line in listing.splitlines():
        if "vhost-b.test" in line and ":" in line:
            idx = line.split(":", 1)[0].strip()
    assert idx is not None, listing
    out = machine.succeed(as_user(f"cogbox l7 del {idx} --name work"))
    assert "Rules reloaded" in out, out
    rc, out = gcurl("--resolve vhost-b.test:443:203.0.113.5 https://vhost-b.test/")
    assert rc != 0, f"vhost-b should be blocked again after del, rc={rc}"

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop l7-origin")

with subtest("Phase G: CLI parser regressions and stub-friendly verbs"):
    # cogbox writes errors to stderr; the test driver's machine.execute()
    # captures only stdout, so we redirect 2>&1 to assert on the message
    # text. Exit codes are still distinct (sysexits values).
    def run_cli(cmd):
        return machine.execute(as_user(cmd + " 2>&1"))

    # G1: status of a not-running default instance -> exit 3, prints "stopped"
    rc, out = run_cli("cogbox status")
    assert rc == 3, f"expected exit 3 (stopped), got {rc}; out={out!r}"
    assert "stopped" in out, out

    # G2: --list and --init-only are removed; both must exit 64 with a
    # redirect-style error message.
    rc, out = run_cli("cogbox --list")
    assert rc == 64, f"expected exit 64, got {rc}; out={out!r}"
    assert "use 'cogbox list'" in out, out
    rc, out = run_cli("cogbox --init-only")
    assert rc == 64, f"expected exit 64, got {rc}; out={out!r}"
    assert "use 'cogbox init'" in out, out

    # G2b: the `run` verb was removed in favor of background-by-default + -f.
    rc, out = run_cli("cogbox run")
    assert rc == 64, f"expected exit 64 for removed 'run', got {rc}; out={out!r}"
    assert "was removed" in out and "-f" in out, out

    # G2c: console/monitor exist as verbs and accept --help (exit 0).
    rc, out = run_cli("cogbox console --help")
    assert rc == 0 and "detach" in out.lower(), out
    rc, out = run_cli("cogbox monitor --help")
    assert rc == 0 and "monitor" in out.lower(), out

    # G3: parser bug -- `--name --vcpu 8` must NOT swallow `--vcpu` as the
    # name. Old bash parser bug; new parser exits 64 with "requires a value".
    rc, out = run_cli("cogbox start --name --vcpu 8")
    assert rc == 64, f"expected exit 64, got {rc}; out={out!r}"
    assert "requires a value" in out, out

    # G4: integer validation on --vcpu; must reject non-numeric with 65.
    rc, out = run_cli("cogbox start --vcpu abc")
    assert rc == 65, f"expected exit 65, got {rc}; out={out!r}"
    assert "positive integer" in out, out

    # G5: unknown flag for a verb -- per-verb scoping, not silent passthrough.
    rc, out = run_cli("cogbox rules list --vcpu 8 --name work")
    assert rc != 0, f"expected nonzero, got {rc}; out={out!r}"

    # G6: list --json emits parseable JSON with one entry per instance
    out = machine.succeed(as_user("cogbox list --json"))
    import json as _json
    parsed = _json.loads(out)
    assert isinstance(parsed, list) and len(parsed) >= 2, parsed
    names = {e["name"] for e in parsed}
    assert "default" in names and "work" in names, names

with subtest("Phase J: bare `cogbox start` waits for sshd then auto-SSHes in"):
    # The new default: daemonize, poll the forwarded SSH port until sshd sends
    # its banner, then exec ssh into the guest. With a non-tty stdin the remote
    # shell reads piped input, so feeding it a command and capturing the output
    # proves the readiness wait + auto-connect work end to end -- in particular
    # that we don't exec ssh before sshd is actually accepting connections.
    # (The foreground init step also prints "Init complete." to stdout, so match
    # on a substring rather than the whole capture.)
    out = machine.succeed(as_user("echo 'uname -n' | cogbox start"), timeout=600)
    assert "cogbox-default" in out, out
    # The VM keeps running after the SSH session ends.
    rc, _ = machine.execute(as_user("cogbox status"))
    assert rc == 0, f"expected running (0) after auto-ssh, got {rc}"
    stop_instance("cc-default")

    # --no-ssh keeps the old behavior: daemonize and return immediately without
    # opening a session. A second start while running reports already-running.
    machine.succeed(as_user("cogbox start --no-ssh"))
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p 2222 root@127.0.0.1 true"), timeout=600
    )
    rc, out = machine.execute(as_user("cogbox start --no-ssh 2>&1"))
    assert rc == 75, f"expected already-running (75), got {rc}; out={out!r}"
    stop_instance("cc-default")
