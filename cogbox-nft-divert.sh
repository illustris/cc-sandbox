#!/bin/sh
# CORRECTED: use REDIRECT (DNAT), NOT TPROXY -- so the enforcer needs NO
# CAP_NET_ADMIN (IP_TRANSPARENT/fwmark would force it). nft-init holds NET_ADMIN
# and DNATs the agent egress to the enforcer's loopback; the enforcer recovers
# the original dst via SO_ORIGINAL_DST (conntrack) on a NORMAL listener.
set -e
PORT=${COGBOX_DIVERT_PORT:-18443}   # == l7proxy loopback listener (base)
nft -f - <<EOF
# NAT table: DNAT the agent's LOCALLY-ORIGINATED egress to the enforcer loopback.
# REDIRECT in OUTPUT targets 127.0.0.1, which matches the l7proxy's 127.0.0.1:base
# listener. The forwarded leg is NOT redirected (REDIRECT in prerouting targets the
# iface addr, not 127.0.0.1) -- it is DROPPED by the FORWARD chain below. The agent
# can't make a tap (no NET_ADMIN), so this loses nothing and is stricter.
table inet cogbox_divert {
  chain output {
    type nat hook output priority -100; policy accept;
    # (the enforcer-cgroup RETURN is inserted by the handshake below, BEFORE the redirect)
    oif "lo" return
    udp dport 53 return
    meta l4proto tcp redirect to :$PORT
  }
}
# FILTER table: nat chains can't drop, so the floor lives here. Local TCP egress
# is left to the nat redirect; UDP (except DNS) + all IPv6 are dropped; ALL
# forwarded traffic is dropped (the nested-VM tap leg -- belt-and-suspenders).
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
# Handshake: exempt the enforcer's OWN egress by cgroup (forge-proof), inserted
# BEFORE the redirect rule in cogbox_divert output.
while [ ! -s /run/cogbox-divert/enforcer.cgroup ]; do sleep 0.2; done
ECG=$(cat /run/cogbox-divert/enforcer.cgroup)
H=$(nft -a list chain inet cogbox_divert output | awk '/redirect to/{print $NF; exit}')
nft insert rule inet cogbox_divert output handle "$H" socket cgroupv2 level 4 "$ECG" return
exec sleep infinity
