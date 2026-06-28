#!/bin/sh
# cogbox container-enforcer nft divert + fail-closed floor (nft-init sidecar PID1).
#
# Uses REDIRECT (DNAT), NOT TPROXY -- so the ENFORCER needs NO CAP_NET_ADMIN
# (IP_TRANSPARENT/fwmark would force it). nft-init (the ONLY privileged container;
# NET_ADMIN/NET_RAW) DNATs the agent's locally-originated egress to the enforcer's
# loopback l7proxy; the enforcer recovers the original dst via SO_ORIGINAL_DST
# (conntrack) on a NORMAL listener.
#
# The enforcer's OWN egress must be EXEMPT (else it loops back into itself). The
# exemption is CGROUP-keyed (forge-proof), NOT uid-keyed: the agent holds
# CAP_SETUID and could setuid() to the enforcer's uid to forge an exempt socket,
# but it cannot move a process into the enforcer's cgroup (that needs write on a
# cgroup outside the agent's delegated subtree) and a nested userns changes uids
# but not the cgroup.
#
# The hard part: k8s gives each container a PRIVATE cgroup namespace, so the
# enforcer's /proc/self/cgroup is "0::/" and we (a different cgroupns) can neither
# see nor name its sibling cgroup. Bridge it by INODE: the enforcer publishes its
# cgroup dir's kernfs inode (global id) over the rw divert volume; we walk the
# HOST cgroup tree (bind-mounted read-only at /sys/fs/cgroup) to find the dir with
# that inode -> the enforcer's REAL host-global path -> key the exemption on it,
# with `level N` computed from the path depth (NOT hardcoded). nft resolves the
# cgroupv2 match path against that same host-rooted /sys/fs/cgroup.

# The fail-closed floor + default-divert load FIRST and MUST succeed (a missing
# floor would leak egress): guard with set -e so nft-init fails loudly if nft
# rejects the ruleset. The cgroup-exemption handshake that follows is made
# resilient (set +e) -- a resolution hiccup leaves the pod UP and inspectable with
# the floor still enforcing (fail-closed: the enforcer's own egress loops, so the
# sandbox simply cannot reach the internet) rather than crashlooping nft-init out
# of `kubectl exec` reach.
set -e
PORT=${COGBOX_DIVERT_PORT:-18443}   # == l7proxy loopback listener (base)
nft -f - <<EOF
# NAT table: DNAT the agent's LOCALLY-ORIGINATED egress to the enforcer loopback.
# REDIRECT in OUTPUT targets 127.0.0.1, matching the l7proxy's 127.0.0.1:base
# listener (the pod shares ONE netns across containers). The forwarded leg is NOT
# redirected -- it is DROPPED by the FORWARD chain below. The agent can't make a
# tap (no NET_ADMIN), so this loses nothing and is stricter.
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
echo "cogbox-nft-divert: fail-closed floor + default REDIRECT(:$PORT) loaded" >&2

# ---- cgroup-keyed enforcer exemption (forge-proof, inode-bridged) -----------
set +e
log() { echo "cogbox-nft-divert: $*" >&2; }
stay_up() {
	log "ERROR: $1"
	log "fail-closed: floor stays enforced (sandbox egress blocked); staying up for inspection"
	log "DIAGNOSTICS:"
	log "  handshake: $(tr '\n' ' ' < /run/cogbox-divert/enforcer.cgroup 2>&1)"
	log "  nft-init /proc/self/cgroup: $(tr '\n' ',' < /proc/self/cgroup 2>&1)"
	log "  /sys/fs/cgroup top: $(ls /sys/fs/cgroup 2>&1 | tr '\n' ' ')"
	log "  POD_UID=${POD_UID:-<unset>}"
	exec sleep infinity
}

# Wait for the enforcer to publish its cgroup inode over the rw divert volume.
i=0
while [ ! -s /run/cogbox-divert/enforcer.cgroup ]; do
	i=$((i + 1)); [ "$i" -gt 600 ] && stay_up "timed out waiting for the enforcer cgroup handshake"
	sleep 0.2
done
INODE=$(awk -F= '/^inode=/{print $2; exit}' /run/cogbox-divert/enforcer.cgroup)
[ -n "$INODE" ] || stay_up "no inode= line in the cgroup handshake"

# Recover the enforcer's REAL (host-global) cgroup path by inode. The host cgroup
# tree is bind-mounted at /sys/fs/cgroup, so nft resolves the cgroupv2 match path
# against the true cgroup root.
CGABS=$(find /sys/fs/cgroup -xdev -type d -inum "$INODE" 2>/dev/null | head -1)
[ -n "$CGABS" ] || stay_up "no cgroup dir with inode $INODE under /sys/fs/cgroup (host cgroup tree mounted?)"
RELPATH=${CGABS#/sys/fs/cgroup}
RELPATH=${RELPATH#/}
[ -n "$RELPATH" ] || stay_up "inode $INODE resolved to the cgroup ROOT ($CGABS); refusing to exempt root"
# level N = the cgroup's depth from the root == number of path components.
LEVEL=$(printf '%s' "$RELPATH" | awk -F/ '{print NF}')
log "enforcer cgroup resolved: inode=$INODE path=/$RELPATH level=$LEVEL"

# Insert the RETURN exemption BEFORE the redirect so the enforcer's own egress
# (and its mitmdump/l7proxy children -- same cgroup) is not looped back. Nested
# agent processes sit DEEPER in the agent's own subtree, so their level-N ancestor
# is the agent scope (not the enforcer) -> they still divert.
H=$(nft -a list chain inet cogbox_divert output | awk '/redirect to/{print $NF; exit}')
[ -n "$H" ] || stay_up "could not find the redirect rule handle"
if nft insert rule inet cogbox_divert output handle "$H" socket cgroupv2 level "$LEVEL" "$RELPATH" return; then
	log "inserted enforcer cgroup exemption (level $LEVEL \"$RELPATH\") before redirect handle $H"
else
	stay_up "failed to insert the cgroup exemption (level $LEVEL \"$RELPATH\")"
fi

exec sleep infinity
