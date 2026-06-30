# NixOS test driver script for the container-mode nft egress-floor bypass suite
# (TODO). `machine`, `start_all`, etc. are injected by the test driver.
start_all()
machine.wait_for_unit("multi-user.target")

# 1. Pin every probe destination on a dummy interface. Assign BEFORE loading the
#    floor so IPv6 setup (DAD skipped via nodad) and any incidental egress is
#    unhindered. The divert/floor OUTPUT hooks still apply to locally-destined
#    packets, which is exactly what the probes exercise.
machine.succeed("ip link add dummy0 type dummy")
machine.succeed("ip link set dummy0 up")
for ip in [
    "10.96.0.10/32", "10.96.12.34/32", "192.0.2.10/32", "192.0.2.20/32",
    "192.0.2.30/32", "198.51.100.10/32", "198.51.100.20/32",
    "198.51.100.30/32", "198.51.100.40/32",
]:
    machine.succeed(f"ip addr add {ip} dev dummy0")
machine.succeed("ip -6 addr add fd00:dead:beef::10/64 dev dummy0 nodad")

# 2. Point the script's resolver discovery at our stub kube-dns ClusterIP.
machine.succeed("rm -f /etc/resolv.conf; printf 'nameserver 10.96.0.10\\n' > /etc/resolv.conf")

# 3. Load the REAL divert+floor ruleset. The script execs `sleep infinity` after an
#    atomic nft load, so background it, then confirm both tables are present.
machine.succeed(
    "COGBOX_ENFORCER_IP=10.96.12.34 COGBOX_ENFORCER_PORT=18443 "
    "setsid sh /etc/cogbox-nft-divert.sh >/tmp/divert.log 2>&1 </dev/null & "
    "sleep 1; "
    "nft list table inet cogbox_floor >/dev/null && "
    "nft list table inet cogbox_divert >/dev/null"
)

# 3a. The floor must be a DEFAULT-DROP allowlist whose ONLY udp/53 accept is pinned
#     to the discovered resolver (no allow-all DNS reopening the exfil channel).
machine.succeed("nft list chain inet cogbox_floor output | grep -F 'policy drop'")
machine.succeed(
    "nft list chain inet cogbox_floor output "
    "| grep -F 'ip daddr 10.96.0.10 udp dport 53 accept'"
)
# An unqualified `udp dport 53 accept` (allow-all) must NOT exist in the floor.
machine.fail(
    "nft list chain inet cogbox_floor output "
    "| grep -E '^[[:space:]]*udp dport 53 accept$'"
)

# 4. Run the in-guest probe harness: it asserts every egress path and exits
#    non-zero (with a PASS/FAIL report) on any leak.
print(machine.succeed("python3 /etc/nft_bypass_probe.py"))

# 5. FAIL-CLOSED: unset enforcer coords -> deny-all floor + exit 64, and the nat
#    divert table is NOT (re)loaded, so TCP egress is dropped.
rc, _ = machine.execute(
    "COGBOX_ENFORCER_IP= COGBOX_ENFORCER_PORT= "
    "sh /etc/cogbox-nft-divert.sh >/tmp/failclosed.log 2>&1"
)
assert rc == 64, f"fail-closed must exit 64, got {rc}"
machine.fail("nft list table inet cogbox_divert")
# The deny-all floor still default-drops TCP egress (no redirect, no tcp accept).
machine.fail(
    "timeout 5 python3 -c "
    "'import socket; socket.create_connection((\"192.0.2.10\", 443), timeout=2)'"
)
# ...but it KEEPS the resolver-only DNS allow (leaks stay closed on this path too).
machine.succeed(
    "nft list chain inet cogbox_floor output "
    "| grep -F 'ip daddr 10.96.0.10 udp dport 53 accept'"
)
