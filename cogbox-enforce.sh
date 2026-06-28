#!/usr/bin/env bash
# cogbox enforce supervisor -- PID1 of the container enforcer sidecar.
#
# Reached via `cogbox enforce -n <name>` (the enforce verb execs us). For ONE
# instance, with NO VM/passt/QEMU: render the wire files, run the L7 terminate
# backend (mitmdump) + the host-side L7 proxy in nft-REDIRECT accept mode, and
# publish the per-instance CA CERT (never the key) so the agent's egress trust
# bundle and the pod readinessProbe unblock.
# S6.1-6.5 and the enforcer blueprint.
#
# Cross-container contract (cogworx renders the 3-container pod to these EXACT
# paths/env; build to them):
#   env     COGBOX_L7_ACCEPT=redirect  COGBOX_DIVERT_PORT=<base>
#           XDG_CONFIG_HOME=<state>/config  COGBOX_INSTANCE=<name>
#           COGBOX_GLOBAL_SECRETS_DIR / COGBOX_INSTANCE_SECRETS_DIR (enforcer-private)
#   mounts  state PVC, rules emptyDir=/run/cogbox-rt, ca-pub=/run/cogbox-capub,
#           divert=/run/cogbox-divert, secrets=/run/cogbox-secrets,
#           ca-conf (mitmproxy confdir)=/run/cogbox-ca-conf
#   probe   readinessProbe = test -f /run/cogbox-capub/ca.crt
#
# Substituted by mkCogbox: @cogbox@ @mitmdump@ @l7addon@.
#
# Intentionally NO `set -e`: this is a long-lived supervisor; a transient child
# failure must restart the child, not abort PID1. The critical setup steps are
# guarded by hand.
set -uo pipefail

log() { echo "cogbox-enforce: $*" >&2; }
die() { log "error: $1"; exit "${2:-70}"; }

# -- Resolve the instance + paths ----------------------------------
# The enforce verb passes the resolved name as $1; $COGBOX_INSTANCE is the
# fallback (what the verb itself falls back to), default "default".
NAME="${1:-${COGBOX_INSTANCE:-default}}"

: "${XDG_CONFIG_HOME:?XDG_CONFIG_HOME must be set (the state PVC config dir)}"
CONFIG="$XDG_CONFIG_HOME/cogbox/instances/$NAME/config.json"
[ -f "$CONFIG" ] || die "no config at $CONFIG" 66

# Enforcer-local runtime (the rules emptyDir) + the contract mount points.
RUNTIME=/run/cogbox-rt
DIVERT_DIR=/run/cogbox-divert
CAPUB_DIR=/run/cogbox-capub
CA_CONF=/run/cogbox-ca-conf

# Port base == the nft REDIRECT target == the l7proxy loopback listener; the
# mitmdump terminate hop sits at base+2 (mirrors the VM's L7_MITM_PORT).
BASE="${COGBOX_DIVERT_PORT:-18443}"
MITM_PORT=$(( BASE + 2 ))

mkdir -p "$RUNTIME" "$DIVERT_DIR" "$CAPUB_DIR" "$CA_CONF"

# -- (a) nft cgroup handshake --------------------------------------
# nft-init loads a fail-closed REDIRECT divert, then waits for THIS file to learn
# the enforcer's cgroup and insert the (forge-proof) RETURN exemption so our own
# egress is not redirected back into us. The divert volume is rw here, ro in
# nft-init, ABSENT from the agent -> the sandbox cannot forge it. Our children
# (mitmdump, l7proxy) share this cgroup, so one write covers them.
cat /proc/self/cgroup > "$DIVERT_DIR/enforcer.cgroup" \
	|| die "failed to write cgroup handshake to $DIVERT_DIR/enforcer.cgroup"

# -- (b) render the wire files -------------------------------------
# The same renderer the hot-reload path uses (no jq/Zig drift). Writes l7-rules
# + l7-inject-conf.json + l7-inject-hosts; the secret-store reads honor the
# COGBOX_*_SECRETS_DIR overrides (enforcer-private store). netfilter-rules is
# emitted too but unused here (no LD_PRELOAD passt in the container).
@cogbox@ __render-rules "$CONFIG" "$RUNTIME" || die "render of $CONFIG failed"

# -- Child management ----------------------------------------------
MITM_PID=""
L7PROXY_PID=""

# mitmdump = the L7 terminate backend, SOCKS5 mode + our enforcement addon.
# confdir is the enforcer-PRIVATE ca-conf volume: mitmproxy self-generates the
# per-instance CA there (cert + key); we publish only the cert below.
# connection_strategy=lazy defers the upstream connect until the addon decides,
# so a denied request never opens an upstream socket. An explicit
# COGBOX_L7_INJECT_CONF wins; else the addon reads the rendered conf (blank when
# absent -> the addon falls back to "guest carries its own token").
start_l7mitm() {
	local inject_conf="${COGBOX_L7_INJECT_CONF:-$RUNTIME/l7-inject-conf.json}"
	[ -f "$inject_conf" ] || inject_conf=""
	COGBOX_L7_RULES="$RUNTIME/l7-rules" \
	COGBOX_L7_INJECT_CONF="$inject_conf" \
	@mitmdump@ --mode "socks5@${MITM_PORT}" --listen-host 127.0.0.1 \
		--set confdir="$CA_CONF" --set http2=false --set connection_strategy=lazy \
		-s "@l7addon@" -q &
	MITM_PID=$!
	echo "$MITM_PID" > "$RUNTIME/l7mitm.pid"
}

# The host-side L7 proxy. It reads COGBOX_L7_ACCEPT=redirect from the pod env ->
# nft-REDIRECT front door: a normal loopback listener on $BASE, original dst
# recovered via SO_ORIGINAL_DST. Writes l7proxy.pid so the hot-reload verbs
# (rule/secret edits kubectl-exec'd into this container) can SIGHUP it.
start_l7proxy() {
	@cogbox@ __l7proxy "$RUNTIME" "$BASE" &
	L7PROXY_PID=$!
	echo "$L7PROXY_PID" > "$RUNTIME/l7proxy.pid"
}

# Publish the CA CERT ONLY (never the key) once mitmproxy mints it, so the
# agent's cogbox-l7-trust + the pod readinessProbe (test -f .../ca.crt) unblock.
# Atomic rename so a reader never sees a half-written cert.
publish_ca() {
	local src="$CA_CONF/mitmproxy-ca-cert.pem"
	local dst="$CAPUB_DIR/ca.crt"
	local i
	for i in $(seq 1 100); do
		[ -s "$src" ] && break
		kill -0 "$MITM_PID" 2>/dev/null || { log "warning: mitmdump exited before minting a CA"; return 1; }
		sleep 0.1
	done
	[ -s "$src" ] || { log "warning: mitmproxy CA cert never appeared at $src"; return 1; }
	# Guard against ever publishing the private key into the agent-readable cert.
	if grep -q "PRIVATE KEY" "$src"; then
		die "refusing to publish CA: $src contains a private key"
	fi
	if cp "$src" "$dst.tmp" && mv "$dst.tmp" "$dst"; then
		log "published CA cert -> $dst"
	else
		log "warning: failed to publish CA cert to $dst"
		return 1
	fi
}

# -- (f) signal handling: forward SIGTERM, tear down ----------------
terminate() {
	log "received termination signal; stopping children"
	[ -n "$L7PROXY_PID" ] && kill "$L7PROXY_PID" 2>/dev/null
	[ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null
	wait 2>/dev/null
	exit 0
}
trap terminate TERM INT

# -- Bring-up + supervise ------------------------------------------
start_l7mitm
publish_ca
start_l7proxy

# Restart whichever child dies. Edits need no restart (the addon mtime-reloads;
# the proxy reloads on SIGHUP) -- only a crash does. `wait -n` returns on any
# child exit OR a trapped signal; on a signal `terminate` has already exited.
# Re-publish the CA after a mitmdump restart (idempotent: the confdir CA
# persists across restarts).
while true; do
	wait -n 2>/dev/null
	if [ -n "$MITM_PID" ] && ! kill -0 "$MITM_PID" 2>/dev/null; then
		log "mitmdump (pid $MITM_PID) exited; restarting"
		start_l7mitm
		publish_ca
	fi
	if [ -n "$L7PROXY_PID" ] && ! kill -0 "$L7PROXY_PID" 2>/dev/null; then
		log "l7proxy (pid $L7PROXY_PID) exited; restarting"
		start_l7proxy
	fi
	sleep 0.2
done
