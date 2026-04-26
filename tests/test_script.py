import shlex

SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=2"
CC_SANDBOX = "/run/current-system/sw/bin/cc-sandbox"


def as_user(cmd):
    return "su - testuser -c " + shlex.quote(cmd)


def probe(ssh_port, ip):
    remote = f"timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/9000'"
    ssh_cmd = f"ssh {SSH_OPTS} -p {ssh_port} root@127.0.0.1 {shlex.quote(remote)}"
    return as_user(ssh_cmd)


def boot_and_wait(unit, args, ssh_port):
    # systemd-run keeps the wrapper + QEMU + passt in one cgroup so
    # `systemctl stop` later tears the whole tree down cleanly.
    machine.succeed(
        f"systemd-run --unit={unit} --uid=testuser "
        "--setenv=HOME=/home/testuser "
        "--working-directory=/home/testuser "
        f"{CC_SANDBOX} {args}"
    )
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p {ssh_port} root@127.0.0.1 true"),
        timeout=600,
    )


def stop_instance(unit, name=None):
    machine.succeed(f"systemctl stop {unit} || true")
    runtime = "/tmp/cc-sandbox" + (("-" + name) if name else "")
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
    # A1: first-run init for the default instance, network=none
    machine.succeed(as_user("yes y | cc-sandbox --init-only --network none"))
    machine.succeed("test -f /home/testuser/.config/cc-sandbox/instances/default/config.json")
    machine.succeed("test -f /home/testuser/.config/cc-sandbox/authorized_keys")
    machine.succeed("test -d /home/testuser/.local/share/cc-sandbox/instances/default")
    machine.succeed("test -f /home/testuser/.claude.json")
    # Old top-level default config must NOT be created any more.
    machine.fail("test -e /home/testuser/.config/cc-sandbox/config.json")
    net = machine.succeed(
        "jq -r .network /home/testuser/.config/cc-sandbox/instances/default/config.json"
    ).strip()
    assert net == "none", f"expected network=none, got {net!r}"

    # A2: --list shows the default instance
    out = machine.succeed(as_user("cc-sandbox --list"))
    assert "(default)" in out, out
    assert "ssh:2222" in out, out
    assert "net:none" in out, out

    # A3: named instance with rules mode -> auto-assigned ports
    machine.succeed(as_user("yes y | cc-sandbox --init-only --name work --network rules"))
    # Named instance data must be a sibling of the default's data dir, not
    # nested inside it. A default-instance boot 9p-shares its data dir into
    # the guest; if named instances live under it, they leak across.
    machine.succeed("test -d /home/testuser/.local/share/cc-sandbox/instances/work")
    machine.fail("test -e /home/testuser/.local/share/cc-sandbox/instances/default/instances")
    ssh_port = machine.succeed(
        "jq -r .sshPort /home/testuser/.config/cc-sandbox/instances/work/config.json"
    ).strip()
    assert ssh_port == "2223", f"expected auto-assigned 2223, got {ssh_port!r}"
    net_kind = machine.succeed(
        "jq -r '.network | type' /home/testuser/.config/cc-sandbox/instances/work/config.json"
    ).strip()
    assert net_kind == "object", f"expected rules object, got {net_kind!r}"

    # A4: --list shows both
    out = machine.succeed(as_user("cc-sandbox --list"))
    assert "(default)" in out and "work" in out, out

    # A5: rules add / list / del on the work instance.
    # Use --at to land the new rules at known positions; otherwise they
    # append after the seeded bogon-deny ruleset and del 1 would remove
    # a seeded rule instead of the test rule. Use 8.8.8.8/32 instead of
    # 0.0.0.0/0 for the second rule so its substring check doesn't
    # collide with the seeded `allow 0.0.0.0/0`.
    machine.succeed(as_user("cc-sandbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    machine.succeed(as_user("cc-sandbox rules add deny 8.8.8.8/32 --at 2 --name work"))
    out = machine.succeed(as_user("cc-sandbox rules list --name work"))
    assert "10.99.0.1/32" in out and "8.8.8.8/32" in out, out
    machine.succeed(as_user("cc-sandbox rules del 1 --name work"))
    out = machine.succeed(as_user("cc-sandbox rules list --name work"))
    assert "10.99.0.1/32" not in out and "8.8.8.8/32" in out, out

    # A6: rules add fails on a non-rules instance (default is network=none)
    machine.fail(as_user("cc-sandbox rules add allow 1.1.1.1/32"))

# Install host pubkey for inner-VM SSH (shared by the default and work instances)
machine.succeed(
    "cp /home/testuser/.ssh/id_ed25519.pub "
    "/home/testuser/.config/cc-sandbox/authorized_keys"
)

with subtest("Phase B: --network none blocks all outbound"):
    boot_and_wait("cc-default", "", ssh_port=2222)
    out = machine.succeed(as_user("cc-sandbox --list"))
    assert "(running)" in out, out
    hostname = machine.succeed(
        as_user(f"ssh {SSH_OPTS} -p 2222 root@127.0.0.1 hostname")
    ).strip()
    assert hostname == "cc-sandbox", f"unexpected inner hostname {hostname!r}"
    machine.fail(probe(2222, "10.99.0.1"))
    machine.fail(probe(2222, "10.99.0.2"))
    stop_instance("cc-default")

with subtest("Phase C: --network full allows outbound"):
    # Reinit the default instance in full mode
    machine.succeed("rm -f /home/testuser/.config/cc-sandbox/instances/default/config.json")
    machine.succeed(as_user("yes y | cc-sandbox --init-only --network full"))
    machine.succeed(
        "cp /home/testuser/.ssh/id_ed25519.pub "
        "/home/testuser/.config/cc-sandbox/authorized_keys"
    )
    boot_and_wait("cc-default", "", ssh_port=2222)
    machine.succeed(probe(2222, "10.99.0.1"))
    machine.succeed(probe(2222, "10.99.0.2"))
    stop_instance("cc-default")

with subtest("Phase D: --network rules with dynamic reload"):
    # work instance carries the seeded bogon-deny ruleset; 10.99.0.0/8
    # falls inside `deny 10.0.0.0/8`, so we need an explicit allow at the
    # front for 10.99.0.1/32 to be reachable.
    machine.succeed(as_user("cc-sandbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    # Initial policy: .1 allowed, .2 denied
    machine.succeed(probe(2223, "10.99.0.1"))
    machine.fail(probe(2223, "10.99.0.2"))

    # Dynamic add: insert allow 10.99.0.2/32 BEFORE the catch-all deny
    out = machine.succeed(as_user("cc-sandbox rules add allow 10.99.0.2/32 --at 2 --name work"))
    assert "Rules reloaded" in out, out
    machine.succeed(probe(2223, "10.99.0.2"))

    # Dynamic delete: drop the .1 allow at position 1
    out = machine.succeed(as_user("cc-sandbox rules del 1 --name work"))
    assert "Rules reloaded" in out, out
    machine.fail(probe(2223, "10.99.0.1"))
    machine.succeed(probe(2223, "10.99.0.2"))

    stop_instance("cc-work", name="work")
