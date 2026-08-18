#!/usr/bin/env bash
# Behavioural test for cogbox-launch.sh's `init` seeding, run without a VM.
#
# Covers two things unit tests cannot:
#
#   1. The PRODUCER half of the host-integration seeds. --no-implicit-dns and
#      --self-addr are what turn the filter's parameterized port-53 allow and
#      the L7 proxy's per-instance floor ON; without a producer both sides are
#      dead code and an image ships the permissive defaults. It also pins the
#      inverse: an init WITHOUT the flags writes exactly the blob it wrote
#      before they existed, which is what keeps the local and k8s backends
#      untouched.
#
#   2. That a launch failure does not echo credential context. Error paths run
#      with secrets in the environment; a diagnostic that interpolates one is a
#      leak into whatever collects the launcher's stderr (on a cloud VM that is
#      a provider-retained serial console).
#
# Usage: test_launch_flags.sh <path-to-cogbox-launch.sh>
# Needs: bash, jq, coreutils. NOT passt/qemu/nix -- every case stops at
# --init-only or fails before the launch.

set -uo pipefail

LAUNCH="${1:?usage: test_launch_flags.sh <cogbox-launch.sh>}"
[ -f "$LAUNCH" ] || { echo "FAIL: no such script: $LAUNCH" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# Run `cogbox-launch.sh` against a private HOME. Echoes nothing; the caller
# reads $out_dir/config.json and $WORK/<tag>.log.
run_init() {
	local tag="$1"; shift
	local home="$WORK/$tag"
	mkdir -p "$home"
	HOME="$home" \
	COGBOX_DATA="$home/data" \
	XDG_CONFIG_HOME="$home/config" \
		bash "$LAUNCH" --init-only --yes "$@" >"$WORK/$tag.log" 2>&1
	echo $?
}

cfg_of() { echo "$WORK/$1/config/cogbox/instances/demo/config.json"; }

# --- 1. no flags: today's blob, unchanged -----------------------------------

rc=$(run_init plain --name demo --network rules)
[ "$rc" = 0 ] || bad "plain init exited $rc (log: $(cat "$WORK/plain.log"))"
plain=$(cfg_of plain)
if [ -f "$plain" ]; then
	[ "$(jq -r '.bindAddr' "$plain")" = "127.0.0.1" ] \
		|| bad "plain init did not keep bindAddr 127.0.0.1"
	[ "$(jq -r '.network | has("implicitDns")' "$plain")" = "false" ] \
		|| bad "plain init wrote an implicitDns key"
	[ "$(jq -r '.network | has("selfAddrs")' "$plain")" = "false" ] \
		|| bad "plain init wrote a selfAddrs key"
	[ "$(jq -r '.network | has("dnsHost")' "$plain")" = "false" ] \
		|| bad "plain init wrote a dnsHost key"
	ok "init without the seeds writes the pre-feature config"
else
	bad "plain init wrote no config.json"
fi

# --- 2. all four flags land in config.json ----------------------------------

rc=$(run_init seeded --name demo --network rules \
	--bind-addr 10.0.0.5 --no-implicit-dns --dns-host 127.0.0.53 \
	--self-addr 10.0.0.5/32 --self-addr 10.0.0.6/32)
[ "$rc" = 0 ] || bad "seeded init exited $rc (log: $(cat "$WORK/seeded.log"))"
seeded=$(cfg_of seeded)
if [ -f "$seeded" ]; then
	[ "$(jq -r '.bindAddr' "$seeded")" = "10.0.0.5" ] \
		|| bad "--bind-addr did not reach .bindAddr"
	[ "$(jq -r '.network.implicitDns' "$seeded")" = "false" ] \
		|| bad "--no-implicit-dns did not reach .network.implicitDns"
	[ "$(jq -c '.network.selfAddrs' "$seeded")" = '["10.0.0.5/32","10.0.0.6/32"]' ] \
		|| bad "--self-addr did not reach .network.selfAddrs in order (got $(jq -c '.network.selfAddrs' "$seeded"))"
	[ "$(jq -r '.network.dnsHost' "$seeded")" = "127.0.0.53" ] \
		|| bad "--dns-host did not reach .network.dnsHost"
	ok "the four seeds land in config.json"

	# ...and they add NOTHING else: strip exactly what they contribute and the
	# blob must equal the flagless one, key for key.
	if [ -f "$plain" ]; then
		stripped=$(jq -S 'del(.network.implicitDns, .network.selfAddrs, .network.dnsHost) | .bindAddr = "127.0.0.1"' "$seeded")
		base=$(jq -S '.' "$plain")
		[ "$stripped" = "$base" ] \
			|| bad "the seeded config differs from the plain one beyond the four seeds"
		ok "the seeds contribute exactly four keys and no other drift"
	fi
else
	bad "seeded init wrote no config.json"
fi

# --- 3. each seed is independent -------------------------------------------

rc=$(run_init dnsonly --name demo --network rules --no-implicit-dns)
[ "$rc" = 0 ] || bad "dns-only init exited $rc (log: $(cat "$WORK/dnsonly.log"))"
dnsonly=$(cfg_of dnsonly)
if [ -f "$dnsonly" ]; then
	[ "$(jq -r '.network.implicitDns' "$dnsonly")" = "false" ] \
		|| bad "--no-implicit-dns alone did not reach .network.implicitDns"
	[ "$(jq -r '.network | has("selfAddrs")' "$dnsonly")" = "false" ] \
		|| bad "--no-implicit-dns alone invented a selfAddrs key"
	[ "$(jq -r '.network | has("dnsHost")' "$dnsonly")" = "false" ] \
		|| bad "--no-implicit-dns alone invented a dnsHost key"
	ok "--no-implicit-dns alone writes only implicitDns"
else
	bad "dns-only init wrote no config.json"
fi

rc=$(run_init selfonly --name demo --network rules --self-addr 10.0.0.5/32)
[ "$rc" = 0 ] || bad "self-addr-only init exited $rc (log: $(cat "$WORK/selfonly.log"))"
selfonly=$(cfg_of selfonly)
if [ -f "$selfonly" ]; then
	[ "$(jq -c '.network.selfAddrs' "$selfonly")" = '["10.0.0.5/32"]' ] \
		|| bad "--self-addr alone did not reach .network.selfAddrs"
	[ "$(jq -r '.network | has("implicitDns")' "$selfonly")" = "false" ] \
		|| bad "--self-addr alone invented an implicitDns key"
	ok "--self-addr alone writes only selfAddrs"
else
	bad "self-addr-only init wrote no config.json"
fi

rc=$(run_init dnshostonly --name demo --network rules --dns-host 127.0.0.53)
[ "$rc" = 0 ] || bad "dns-host-only init exited $rc (log: $(cat "$WORK/dnshostonly.log"))"
dnshostonly=$(cfg_of dnshostonly)
if [ -f "$dnshostonly" ]; then
	[ "$(jq -r '.network.dnsHost' "$dnshostonly")" = "127.0.0.53" ] \
		|| bad "--dns-host alone did not reach .network.dnsHost"
	[ "$(jq -r '.network | has("implicitDns")' "$dnshostonly")" = "false" ] \
		|| bad "--dns-host alone invented an implicitDns key"
	ok "--dns-host alone writes only dnsHost"
else
	bad "dns-host-only init wrote no config.json"
fi

# --- 4. full mode: the rules-only seeds are refused loudly ------------------

rc=$(run_init fullmode --name demo --network full --no-implicit-dns --dns-host 127.0.0.53 --self-addr 10.0.0.5/32)
[ "$rc" = 0 ] || bad "full-mode init exited $rc (log: $(cat "$WORK/fullmode.log"))"
fullcfg=$(cfg_of fullmode)
if [ -f "$fullcfg" ]; then
	[ "$(jq -r '.network' "$fullcfg")" = "full" ] \
		|| bad "full-mode init did not keep .network == \"full\""
	grep -qi "rules.*mode only\|apply to \"rules\" mode only" "$WORK/fullmode.log" \
		|| bad "full-mode init dropped the seeds silently (no warning in the log)"
	ok "the rules-only seeds are refused with a warning in full mode"
else
	bad "full-mode init wrote no config.json"
fi

# --- 5. the passt knobs reach BOTH modes ------------------------------------
#
# Static, because starting passt needs a VM. Worth pinning anyway: `full` mode
# is the one with no L4 filter at all, so wiring the uid and guest-DNS knobs
# into `rules` only would leave the hole open exactly where nothing else covers
# it. Asserting the invocation count too, so a third one cannot slip by
# unchecked.

n_passt=$(grep -c 'passt --foreground' "$LAUNCH")
if [ "$n_passt" -ne 2 ]; then
	bad "expected 2 passt invocations in the launcher, found $n_passt"
else
	missing=0
	while IFS= read -r ln; do
		window=$(sed -n "${ln},$((ln + 2))p" "$LAUNCH")
		for tok in PASST_RUNAS_ARGS PASST_DNS_ARGS PASST_FWD_PREFIX; do
			case "$window" in
				*"$tok"*) ;;
				*) bad "passt invocation at line $ln does not carry $tok"; missing=1 ;;
			esac
		done
	done < <(grep -n 'passt --foreground' "$LAUNCH" | cut -d: -f1)
	[ "$missing" -eq 0 ] && ok "both passt invocations carry the uid / guest-DNS / bind knobs"
fi

# --- 5b. guest DNS is FORWARDED to the host, never handed over raw ----------
#
# THE REGRESSION THIS SECTION EXISTS FOR. The guest must resolve what the HOST
# resolves, so an internal name resolves to its internal address -- parity with
# the local and k8s backends. That holds only if passt INTERCEPTS the guest's
# queries and re-emits them to a resolver on the host:
#
#   --dns-forward <addr>   the address the guest is told to use, which passt
#                          consumes at the tap. A handle, not a route.
#   --dns-host <addr>      where passt re-emits them: the host's own forwarder.
#
# `-D <addr>` is the shape that FAILS the property, and it fails it silently:
# passt applies -D before reading /etc/resolv.conf and then skips the read
# (conf.c get_dns()'s `dns4_set` short-circuit), so dns_host is left unspecified
# and no forwarding happens at all -- the guest is handed a raw address it must
# reach on its own, which on a host whose real resolver is fenced off means a
# PUBLIC resolver and no internal names. Static, because proving it at runtime
# needs a VM; here the spelling IS the mechanism, so checking the spelling is
# not a proxy for the behaviour.

dnsblock=$(sed -n '/^PASST_DNS_ARGS=()/,/^fi$/p' "$LAUNCH")
if [ -z "$dnsblock" ]; then
	bad "could not find the PASST_DNS_ARGS construction in the launcher"
else
	case "$dnsblock" in
		*'--dns-forward'*) ok "the guest resolver is advertised via --dns-forward, so passt intercepts the guest's queries" ;;
		*) bad "the guest resolver is not passed as --dns-forward; the guest would have to reach it itself: $dnsblock" ;;
	esac
	case "$dnsblock" in
		*'--dns-host'*) ok "the intercepted queries are re-emitted to the host's own forwarder (--dns-host)" ;;
		*) bad "no --dns-host: passt would have no pinned forwarding target and guest DNS would follow whatever resolv.conf named: $dnsblock" ;;
	esac
	case "$dnsblock" in
		*'--no-map-gw'*) ok "the gateway mapping stays closed (--no-map-gw travels with the resolver knob)" ;;
		*) bad "--no-map-gw is no longer applied with the guest resolver; passt's gateway->loopback mapping would reopen in both modes: $dnsblock" ;;
	esac
	# The refusal, stated as its own case: -D is the pre-fix spelling, and
	# re-adding it disarms passt's forwarding while changing nothing else that
	# any other assertion here can see.
	case "$dnsblock" in
		*' -D '*) bad "the launcher passes passt -D, which skips /etc/resolv.conf and leaves dns_host unspecified: guest DNS stops being forwarded to the host and reverts to a raw (public) resolver: $dnsblock" ;;
		*) ok "passt -D is not used, so get_dns() still runs and passt's own forwarding stays armed" ;;
	esac
	# And the whole thing stays behind the knob: an unset COGBOX_GUEST_RESOLVER
	# must add nothing, which is what keeps the local, k8s and container argv
	# byte-identical to what they ran before any of this existed.
	case "$dnsblock" in
		*'if [ -n "${COGBOX_GUEST_RESOLVER:-}" ]; then'*) ok "the whole DNS block is gated on COGBOX_GUEST_RESOLVER, so an unset knob adds no argv" ;;
		*) bad "the DNS args are not gated on COGBOX_GUEST_RESOLVER; a local or k8s launch would change argv: $dnsblock" ;;
	esac
fi

# --- 6. failure paths must not echo credential context ----------------------

CANARY="cogbox-canary-do-not-log"

# A canary check over a path that did not actually fail proves nothing, so
# each case also asserts the failure it is supposed to be exercising.
canary_free() {
	local tag="$1" log="$2" rc="$3" marker="$4"
	[ "$rc" != 0 ] || bad "$tag did not fail (exit 0) -- the canary check would be vacuous"
	grep -q "$marker" "$log" || bad "$tag did not take the expected error path ($marker)"
	if grep -q "$CANARY" "$log"; then
		bad "$tag leaked the canary: $(grep -n "$CANARY" "$log" | head -3)"
	else
		ok "$tag emits no line carrying the canary"
	fi
}

# (a) unexpected argument (exit 70)
home="$WORK/canary-a"; mkdir -p "$home"
HOME="$home" COGBOX_DATA="$home/data" XDG_CONFIG_HOME="$home/config" \
	COGBOX_NETRC_FILE="/nonexistent/$CANARY" \
	COGBOX_L7_INJECT_CONF="/nonexistent/$CANARY.json" \
	AUTH_TOKEN="$CANARY" \
	bash "$LAUNCH" --init-only --yes --bogus-flag x >"$WORK/canary-a.log" 2>&1
canary_free "unexpected-argument failure" "$WORK/canary-a.log" "$?" "unexpected argument"

# (b) launch against a corrupt config (exit 70 from the JSON gate)
home="$WORK/canary-b"; mkdir -p "$home/config/cogbox/instances/demo"
printf 'not json' > "$home/config/cogbox/instances/demo/config.json"
HOME="$home" COGBOX_DATA="$home/data" XDG_CONFIG_HOME="$home/config" \
	COGBOX_NETRC_FILE="/nonexistent/$CANARY" \
	AUTH_TOKEN="$CANARY" \
	bash "$LAUNCH" --yes --name demo >"$WORK/canary-b.log" 2>&1
canary_free "corrupt-config launch failure" "$WORK/canary-b.log" "$?" "invalid JSON"

# (c) unwritable home (the identity guard, exit 78)
HOME="/nonexistent-home-for-cogbox-test" \
	COGBOX_DATA="$WORK/canary-c/data" XDG_CONFIG_HOME="$WORK/canary-c/config" \
	COGBOX_NETRC_FILE="/nonexistent/$CANARY" \
	AUTH_TOKEN="$CANARY" \
	bash "$LAUNCH" --init-only --yes >"$WORK/canary-c.log" 2>&1
canary_free "unwritable-home failure" "$WORK/canary-c.log" "$?" "is not writable"

# --- 7. launch-only directory grants fail before runner/QEMU setup ----------

rc=$(run_init add-dir-reject --name demo --network rules)
[ "$rc" = 0 ] || bad "add-dir rejection fixture init exited $rc (log: $(cat "$WORK/add-dir-reject.log"))"
home="$WORK/add-dir-reject"
runner_probe="$WORK/runner-must-not-be-read"

check_add_dir_rejection() {
	local tag=$1 expected_rc=$2 marker=$3 rejected_path=$4 payload_canary=$5
	local log="$WORK/$tag.log"
	shift 5
	HOME="$home" COGBOX_DATA="$home/data" XDG_CONFIG_HOME="$home/config" \
		RUNNER_DIR="$runner_probe" \
		bash "$LAUNCH" --yes --name demo "$@" >"$log" 2>&1
	local rc=$?
	[ "$rc" = "$expected_rc" ] \
		|| bad "$tag exited $rc, expected $expected_rc (log: $(cat "$log"))"
	grep -Fq "$marker" "$log" \
		|| bad "$tag did not reach the intended diagnostic '$marker' (log: $(cat "$log"))"
	grep -Fq "$rejected_path" "$log" \
		|| bad "$tag diagnostic did not name the rejected path $rejected_path"
	if [ -n "$payload_canary" ] && grep -Fq "$payload_canary" "$log"; then
		bad "$tag echoed file contents instead of naming only $rejected_path"
	fi
	if grep -Fq "$runner_probe" "$log"; then
		bad "$tag reached the substituted runner path instead of rejecting before QEMU setup"
	fi
	ok "$tag rejects before runner/QEMU setup with exit $expected_rc"
}

missing="$home/does-not-exist-add-dir"
check_add_dir_rejection "missing additional directory" 66 \
	"missing or inaccessible" "$missing" "" \
	--add-dir "$missing"

regular="$home/not-a-directory-add-dir"
regular_canary="regular-file-payload-must-not-be-logged"
printf '%s' "$regular_canary" > "$regular"
check_add_dir_rejection "regular-file additional directory" 65 \
	"requires a directory" "$regular" "$regular_canary" \
	--add-dir-ro "$regular"

overlap="$home/data"
overlap_canary="overlap-payload-must-not-be-logged"
printf '%s' "$overlap_canary" > "$overlap/secret-payload"
check_add_dir_rejection "Cogbox-data overlap" 65 \
	"overlaps protected host path" "$overlap" "$overlap_canary" \
	--add-dir "$overlap"

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all launch-flag checks passed"
