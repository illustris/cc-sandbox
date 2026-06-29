#!/bin/sh
# cogbox separate-pod enforcer nft divert + fail-closed floor (nft-init sidecar PID1).
#
# Uses REDIRECT (DNAT), NOT TPROXY -- so NOTHING downstream needs CAP_NET_ADMIN
# beyond this one sidecar (IP_TRANSPARENT/fwmark would force it). nft-init (the
# ONLY privileged container; NET_ADMIN/NET_RAW) DNATs the agent's locally-
# originated TCP egress to the in-pod divert shim (`cogbox __divertshim`, a
# no-caps sidecar on the SAME pod netns). The shim recovers the original dst via
# SO_ORIGINAL_DST (conntrack) and carries it over a SOCKS5 hop to the SEPARATE
# enforcer pod for L7 enforcement.
#
# The enforcer carve-out (validated): the shim's own SOCKS5
# connection to the enforcer must NOT be redirected back into the shim, else it
# loops. Exempt it by destination = the enforcer's STABLE ClusterIP:port. The CNI's
# socket-LB does NOT rewrite the in-pod OUTPUT netfilter hook's view (the
# ClusterIP -> backend DNAT is downstream in eBPF tc), so the in-pod nft hook sees
# the ClusterIP and the exemption matches across enforcer-pod restarts -- no
# pod-IP refresh. This replaces the old cgroup-keyed handshake entirely.
#
# nft-init image PATH carries nft + ip + coreutils + /bin/sh ONLY (no grep/awk/
# find): this script uses nft alone, with absolute paths nowhere required (PATH is
# set by the image). The fail-closed floor + divert load ATOMICALLY (one nft -f
# transaction, `flush ruleset`-first so it is idempotent across restarts with no
# open window); guard with set -e so nft-init fails loudly if nft rejects them.
set -e
PORT="${COGBOX_DIVERT_PORT:-18443}"       # == the in-pod shim's loopback listener (REDIRECT target)
ENFORCER_IP="${COGBOX_ENFORCER_IP:-}"     # the enforcer Service ClusterIP (stable VIP)
ENFORCER_PORT="${COGBOX_ENFORCER_PORT:-}" # the enforcer l7proxy SOCKS5 port (== its base)

# Fail-closed if the enforcer carve-out coordinates are missing: without them the
# exemption rule is malformed and the atomic load would leave the netns with NO
# rules at all (open egress). Load a deny-all floor (TCP egress dropped; only lo +
# DNS pass) first, then refuse to start, so a misconfig blocks egress rather than
# leaking it.
if [ -z "$ENFORCER_IP" ] || [ -z "$ENFORCER_PORT" ]; then
	nft -f - <<'EOF'
flush ruleset
table inet cogbox_floor {
  chain output {
    type filter hook output priority mangle; policy drop;
    oif "lo" accept
    udp dport 53 accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
EOF
	echo "cogbox-nft-divert: FATAL: COGBOX_ENFORCER_IP/PORT unset; loaded deny-all floor and refusing to start" >&2
	exit 64
fi

nft -f - <<EOF
flush ruleset

# NAT table: DNAT the agent's LOCALLY-ORIGINATED TCP egress to the in-pod shim.
# REDIRECT in OUTPUT maps locally-originated packets to 127.0.0.1, matching the
# shim's 127.0.0.1:$PORT listener (the pod shares ONE netns across containers).
# The forwarded leg is NOT redirected -- it is DROPPED by the FORWARD chain below.
table inet cogbox_divert {
  chain output {
    type nat hook output priority -100; policy accept;
    # Enforcer carve-out FIRST: the shim's own SOCKS5 connect to the enforcer
    # ClusterIP must pass through un-redirected (anti-loop). Stable VIP -- see header.
    ip daddr $ENFORCER_IP tcp dport $ENFORCER_PORT counter return
    oif "lo" return
    udp dport 53 return
    meta l4proto tcp redirect to :$PORT
  }
}
# FILTER table: nat chains can't drop, so the floor lives here. Local TCP egress
# is left to the nat redirect; UDP (except DNS) + all IPv6 are dropped; ALL
# forwarded traffic is dropped (belt-and-suspenders -- the agent holds no NET_ADMIN
# to make a tap, but keep the FORWARD drop regardless).
table inet cogbox_floor {
  chain output {
    type filter hook output priority mangle; policy accept;
    meta nfproto ipv6 reject
    oif "lo" accept
    udp dport 53 accept
    meta l4proto udp drop
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
EOF
echo "cogbox-nft-divert: fail-closed floor + REDIRECT(:$PORT) loaded; enforcer carve-out $ENFORCER_IP:$ENFORCER_PORT" >&2

# nft rules persist in the shared pod netns for the pod's lifetime; this sidecar
# just needs to stay up (k8s native sidecar = a never-exiting initContainer).
exec sleep infinity
