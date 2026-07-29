#!/usr/bin/env bash
# Behavioural test for gce/floor.nix. Everything asserted here is a property of
# the rendered ruleset or of a probe's polarity, and neither is visible in the
# unit file.
#
# The cases pin five invariants:
#
#   1. Rule 2 carries a skuid match so socket-less kernel replies can break past
#      it, while still covering every real uid with a range.
#   2. The control-uid exception proves not-blocked before passt starts; deny
#      probes keep the opposite polarity.
#   3. The every-uid range must not be narrowed to named accounts.
#   4. `ct direction original` keeps a real listener's SYN-ACK out of the deny;
#      this requires a real listener because an empty port returns a socket-less
#      RST and cannot distinguish the rule shapes.
#   5. Rule 3 covers loopback for the passt uid while preserving the L7 funnel.
#
# An in-guest probe of the VM's own address reaches the guest because passt
# gives the guest that address over DHCP. Use the SSH host key or a host-only
# port when distinguishing the guest and host endpoints.
#
# Usage: test_floor.sh <path-to-cogworx-floor-install> <path-to-cogworx-floor-verify>
# Needs: bash, coreutils, gnugrep for sections 1-4, which are NOT GCE and NOT
# netfilter -- the metadata server is a file:// tree and the ruleset is never
# loaded. Section 5 additionally needs unshare/ip/nft and a kernel with nftables
# plus conntrack; it loads the real ruleset in a throwaway user+network namespace
# (never the host's) and SKIPS, loudly, when that is unavailable.

set -uo pipefail

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# --- section 5's child, re-exec'd inside `unshare -Urn` ----------------------
#
# Everything below this branch runs in a THROWAWAY user+network namespace: the
# host's ruleset, addresses and routes are never touched, and the branch is
# reached only from section 5 at the bottom of this file. It is up here because
# the script re-execs ITSELF to enter the namespace, so the dispatch has to
# precede the argument parsing.
if [ "${1:-}" = --live-child ]; then
	VERIFY="$2"
	run="$3"
	nft_src="$run/cogworx-floor.nft"
	SELF=192.0.2.10
	echo "LIVE-BEGIN"

	ip link set lo up 2>/dev/null || { echo "LIVE-SKIP: cannot bring up lo"; exit 77; }
	ip addr add "$SELF/32" dev lo 2>/dev/null || { echo "LIVE-SKIP: cannot assign $SELF"; exit 77; }

	# The ONLY edit made to the RULESET under test, and it is confined to the
	# rules that name the cogbox-passt ACCOUNT (rule 1, and rule 3's three
	# lines): that account exists on a GCE image and not on a build machine, and
	# nft refuses to load a ruleset naming an unknown user. Rewriting that
	# selector to a numeric uid nobody here runs as leaves those rules loaded but
	# inert, and leaves rule 2 byte identical to what the installer rendered.
	# `$1`, when given, is the extra sed program that MUTATES a rule for a
	# negative control -- including re-pointing 65533 at uid 0 when it is rule 3
	# rather than rule 2 that is under test.
	load() {
		local -a extra=()
		[ $# -gt 0 ] && extra=(-e "$1")
		sed -e 's/meta skuid "cogbox-passt"/meta skuid 65533/' \
			${extra[@]+"${extra[@]}"} "$nft_src" > "$run/live.nft"
		nft -f "$run/live.nft" 2>&1
	}
	# The real ExecStartPost, run against the real loaded ruleset, with ONE
	# substitution: `setpriv --clear-groups` calls setgroups(2), which is
	# permanently denied inside an unprivileged user namespace, and setpriv
	# refuses `--regid` without some group flag -- so every probe would die
	# before opening a socket. `--keep-groups` makes no other difference here:
	# the floor selects on skuid, never on skgid.
	sed 's/--clear-groups/--keep-groups/' "$VERIFY" > "$run/verify"
	chmod +x "$run/verify"
	if [ "$(grep -c -- --keep-groups "$run/verify")" != 1 ] || ! grep -q -- '--reuid' "$run/verify"; then
		bad "live: the verifier's setpriv line is not the shape this section rewrites: $(grep -n setpriv "$run/verify")"
	fi
	# Its rc is dropped on purpose: probes 1-3 setpriv to cogbox-passt and
	# cogbox-proxy, which do not exist here, so they always fail in this
	# namespace. Only the two probes that run as the control uid are meaningful
	# here, and they are asserted by name.
	verify_out() { COGWORX_RUN_DIR="$run" "$run/verify" 2>&1; }

	# A REAL listener on this machine's loopback, plus one classified connect
	# against it, for the rule-3 cases. Same discipline as probe 5 and for the
	# same reason: an empty port answers a socket-less kernel RST that BREAKs out
	# of any skuid rule, so it reads "refused" whether the rule is present or
	# absent. Only a real socket tells the two apart.
	LO_PID=""
	lo_listen() {
		timeout 20 systemd-socket-activate -l "${2:-127.0.0.1}:$1" --accept true >/dev/null 2>&1 &
		LO_PID=$!
	}
	lo_stop() {
		[ -n "$LO_PID" ] || return 0
		kill "$LO_PID" 2>/dev/null || true
		wait "$LO_PID" 2>/dev/null || true
		LO_PID=""
	}
	# The verifier's classifier, repeated for this uid rather than shared: a DROP
	# makes the connect hang until `timeout` gives up (rc 124), a closed but
	# reachable port answers RST immediately.
	conn() {
		local rc=0
		timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1 || rc=$?
		case "$rc" in
			0) echo open ;;
			124) echo blocked ;;
			*) echo refused ;;
		esac
	}
	# Bring a listener up and wait for it to bind, WITHOUT treating "not bound
	# yet" and "the floor dropped it" as the same answer: only `refused` means
	# keep waiting.
	lo_wait() {
		local port="$1" addr="${2:-127.0.0.1}" got=refused
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			got=$(conn "$addr" "$port")
			[ "$got" = refused ] || break
			sleep 0.2
		done
		echo "$got"
	}

	if ! out=$(load); then
		echo "LIVE-SKIP: nft could not load the rendered ruleset here: $out"
		exit 77
	fi
	# Rule 1 plus rule 3's five lines. If this count moves, either a rule that
	# names the passt uid was added (fine -- update it) or the rewrite is landing
	# somewhere it should not, which would silently change the rule under test.
	if [ "$(grep -c 'meta skuid 65533' "$run/live.nft")" != 6 ]; then
		bad "live: the passt-uid rewrite did not land on exactly the six rules that name that account: $(cat "$run/live.nft")"
	fi

	# CASE 1 -- THE DEFECT. A REAL LISTENER on an exempt port (bound by probe 5
	# itself, root-owned exactly as passt's pre-drop forward is), and a connect
	# from the control uid that must COMPLETE. An empty port cannot substitute:
	# its answer is a socket-less kernel RST that BREAKs past the deny, which is
	# how the broken rule passed review twice.
	out=$(verify_out)
	case "$out" in
		*'exempt-port return path verified'*)
			ok "live: the control uid COMPLETES a connection to a real listener on an exempt port" ;;
		*) bad "live: the control uid could not complete a connection to a real listener on the exempt port. Verifier said: $out" ;;
	esac
	case "$out" in
		*'PROBE FAILED: rule 2 control-uid exception'*)
			bad "live: the empty-port exception probe failed on a correct ruleset: $out" ;;
		*) ok "live: the empty-port exception probe still passes (RST, not a drop)" ;;
	esac

	# CASE 2 -- THE NEGATIVE CONTROL FOR THE FIX ITSELF. Remove exactly the
	# direction scoping and the shipped defect is back; the same probe must now
	# FAIL, and must fail as a DROP (rc 124 -> "blocked"), which is what the live
	# VM showed. The second assertion is the point of the whole section: the
	# empty-port probe stays GREEN under the broken rule, so a suite without a
	# listener reports a healthy floor over a dead `cogbox ssh`.
	if ! out=$(load 's/ ct direction original//'); then
		bad "live: could not load the pre-fix ruleset: $out"
	else
		out=$(verify_out)
		case "$out" in
			*'PROBE FAILED: rule 2 exempt-port return path'*'was blocked'*)
				ok "live: the shipped defect (a deny without the direction scoping) is CAUGHT -- the return SYN-ACK is dropped and the connect times out" ;;
			*) bad "live: a deny that swallows the return SYN-ACK was NOT caught by the probes: $out" ;;
		esac
		case "$out" in
			*'PROBE FAILED: rule 2 control-uid exception'*)
				bad "live: the empty-port probe fired on the broken rule; the case no longer demonstrates the false pass: $out" ;;
			*) ok "live: the empty-port probe stays green on the BROKEN deny (the false pass this section exists to end)" ;;
		esac
	fi

	# CASE 3 -- A NON-EXEMPT UID, same address, same port, same live listener.
	# Modelled by renaming the uid the exception NAMES, because a build sandbox
	# maps exactly one uid and no `nixbld*` can be impersonated here; the deny is
	# a range, so every uid the accept does not name sees precisely this ruleset.
	# It must still be DROPPED -- the fix admits a reply, never an initiation.
	if ! out=$(load 's/meta skuid "root" ip daddr/meta skuid 4242 ip daddr/'); then
		bad "live: could not load the foreign-uid ruleset: $out"
	else
		out=$(verify_out)
		case "$out" in
			*'PROBE FAILED: rule 2 exempt-port return path'*'was blocked'*)
				ok "live: a uid the exception does not name is still DROPPED opening a flow to the same address and port, with a real listener bound" ;;
			*) bad "live: a uid outside the exception reached a live listener on the VM's own address: $out" ;;
		esac
		case "$out" in
			*'PROBE FAILED: rule 2 control-uid exception'*)
				ok "live: the empty-port probe also fails for a uid the exception does not name" ;;
			*) bad "live: an unnamed uid was not blocked reaching the exempt port: $out" ;;
		esac
	fi

	# CASE 4 -- RULE 3, THE LOOPBACK LEG (defect 5), against a REAL listener and
	# with the before/after that makes it evidence rather than a shape claim.
	#
	# Rule 3 names the passt uid, which does not exist here, so the base rewrite
	# has already parked it on 65533; the extra program re-points that at uid 0,
	# the uid this child runs as, so the rule under test actually covers our
	# probes. The listener is bound and proven REACHABLE under the previous
	# ruleset FIRST -- without that, "blocked" afterwards is indistinguishable
	# from a listener that never came up, and the case would pass on a floor that
	# does nothing.
	#
	# The target is l7base+2, the mitmproxy SOCKS5 terminate hop: it sits INSIDE
	# the window the funnel exception spans, so a drop here also proves the
	# exception is a SET of the funnel's own targets and not a port range that
	# swallowed the third port of every triple with them. A guest that reached
	# that hop would hold the terminate tier's raw upstream with no vetting.
	MITM=18445
	FUNNEL=18443
	lo_listen "$MITM"
	got=$(lo_wait "$MITM")
	if [ "$got" != open ]; then
		lo_stop
		echo "LIVE-SKIP: could not bind a loopback listener on $MITM here (got $got)"
		exit 77
	fi
	if ! out=$(load 's/meta skuid 65533/meta skuid 0/'); then
		bad "live: could not load the rule-3-on-this-uid ruleset: $out"
	else
		got=$(conn 127.0.0.1 "$MITM")
		case "$got" in
			blocked)
				ok "live: rule 3 DROPS a flow this uid opens to a live listener on loopback, inside the funnel window and outside the funnel ports" ;;
			*) bad "live: rule 3 did not stop a connect to a live loopback listener on $MITM (got $got); the guest->loopback path rests on passt alone" ;;
		esac
	fi
	lo_stop

	# CASE 5 -- THE FUNNEL EXCEPTION, and the two ways a rule 3 can close the
	# hole by killing the L7 remap funnel with it. Same uid rewrite, same real
	# listener, on the funnel's own target this time (l7base, what the shim
	# rewrites guest 443 to). This is the only case here that can fail on a rule
	# 3 which is "secure" and unusable.
	lo_listen "$FUNNEL"
	got=$(lo_wait "$FUNNEL")
	case "$got" in
		open) ok "live: the L7 funnel's own loopback target is still reachable under rule 3" ;;
		*) bad "live: rule 3 broke the L7 remap funnel -- a connect to the funnel target $FUNNEL was $got, expected open" ;;
	esac

	# NEGATIVE CONTROL A: delete the exception and the funnel dies. Without this
	# the case above would also pass on a rule 3 that never denied anything.
	if ! out=$(load 's/meta skuid 65533/meta skuid 0/; /cogworx-floor-rule3-l7-funnel/d'); then
		bad "live: could not load the exception-less ruleset: $out"
	else
		got=$(conn 127.0.0.1 "$FUNNEL")
		case "$got" in
			blocked) ok "live: deleting the funnel exception DOES kill the funnel, so the accept above the deny is load-bearing" ;;
			*) bad "live: the funnel target was still $got with the exception deleted; this case no longer shows the accept matters" ;;
		esac
	fi

	# NEGATIVE CONTROL B: keep the exception, drop the direction scoping, and the
	# funnel dies anyway -- for exactly the reason the stateless rule-2 deny killed
	# `cogbox ssh`. The funnel's SYN-ACK comes back from a real l7proxy socket
	# with daddr 127.0.0.1 and the CLIENT's ephemeral port, which no dport accept
	# can match, so a stateless rule-3 deny eats every funnel reply while passing
	# every shape check and the deny case above.
	if ! out=$(load 's/meta skuid 65533/meta skuid 0/; s/ ct direction original//'); then
		bad "live: could not load the stateless rule-3 ruleset: $out"
	else
		got=$(conn 127.0.0.1 "$FUNNEL")
		case "$got" in
			blocked) ok "live: a rule-3 deny without the direction scoping eats the funnel's own SYN-ACK -- the rule-2 outage's shape, caught here before it ships" ;;
			*) bad "live: a stateless rule-3 deny did not break the funnel (got $got); the direction scoping's necessity is no longer demonstrated" ;;
		esac
	fi
	lo_stop

	# CASE 6 -- THE DNS-FORWARDER EXCEPTION, measured against a real listener,
	# with the negative control on the SAME PORT at a different loopback address.
	# That pairing is the whole value here: it is what tells "the accept is one
	# socket" apart from "the accept is port 53 on loopback", and the two are
	# indistinguishable in any case that probes 127.0.0.53 alone. A port-53
	# loopback pass would be a hole -- 127.0.0.1 is where l7proxy and the
	# mitmproxy hop live, and a guest that could name a port there has the
	# terminate tier's raw upstream.
	#
	# Last, and soft on a bind failure: port 53 is privileged, so a sandbox that
	# cannot grant CAP_NET_BIND_SERVICE loses this case rather than the section.
	FWD_ADDR=127.0.0.53
	FWD_PORT=53
	if ! out=$(load 's/meta skuid 65533/meta skuid 0/'); then
		bad "live: could not load the rule-3-on-this-uid ruleset for the DNS case: $out"
	else
		lo_listen "$FWD_PORT" "$FWD_ADDR"
		got=$(lo_wait "$FWD_PORT" "$FWD_ADDR")
		if [ "$got" = refused ]; then
			echo "ok   - live: SKIPPED the DNS-forwarder case (cannot bind $FWD_ADDR:$FWD_PORT here)"
			lo_stop
		else
			case "$got" in
				open) ok "live: the passt uid reaches the host DNS forwarder at $FWD_ADDR:$FWD_PORT under rule 3" ;;
				*) bad "live: rule 3 blocked the host DNS forwarder ($FWD_ADDR:$FWD_PORT was $got); every guest on the VM would resolve nothing" ;;
			esac
			lo_stop
			# The negative control: same port, the OTHER loopback address, a real
			# listener again. Blocked is the required answer.
			lo_listen "$FWD_PORT" 127.0.0.1
			got=$(lo_wait "$FWD_PORT" 127.0.0.1)
			case "$got" in
				blocked) ok "live: port 53 at 127.0.0.1 stays DROPPED, so the exception is one socket and not a loopback DNS pass" ;;
				refused) echo "ok   - live: SKIPPED the DNS negative control (no listener bound on 127.0.0.1:$FWD_PORT)" ;;
				*) bad "live: port 53 to 127.0.0.1 was $got; rule 3's DNS exception has widened into a port-53 loopback pass" ;;
			esac
			lo_stop
		fi
	fi

	[ "$fails" -eq 0 ] || exit 1
	exit 0
fi

INSTALL="${1:?usage: test_floor.sh <install> <verify>}"
VERIFY="${2:?usage: test_floor.sh <install> <verify>}"
[ -x "$INSTALL" ] || { echo "FAIL: not executable: $INSTALL" >&2; exit 1; }
[ -x "$VERIFY" ] || { echo "FAIL: not executable: $VERIFY" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

# Render one ruleset. `$1` is a case name, `$2` the cogworx-self-addrs body (an
# empty string means the attribute exists but is empty; the literal word ABSENT
# means the key is not there at all). Echoes the run dir.
#
# The metadata server is a file:// tree, so real curl is exercised with no
# stub and no network. The provider fallback (instance/network-interfaces/) is
# deliberately NOT servable this way -- curl cannot read a directory -- which is
# exactly the "provider named nothing either" case the empty-set fail-closed
# exists for.
render() {
	local name="$1" body="$2"
	local md="$ROOT/$name/md" run="$ROOT/$name/run"
	mkdir -p "$md/instance/attributes" "$run"
	if [ "$body" != ABSENT ]; then
		printf '%s' "$body" > "$md/instance/attributes/cogworx-self-addrs"
	fi
	# The nft load ALWAYS fails here: a build sandbox holds no CAP_NET_ADMIN.
	# That is fine and is why the rc is dropped -- the rendered file is written
	# before the load is attempted, and the rendered file is the artifact under
	# test. Nothing in this script asserts on the installer's exit status.
	COGWORX_MD_BASE="file://$md" COGWORX_RUN_DIR="$run" \
		"$INSTALL" >"$ROOT/$name.out" 2>&1
	echo "$run"
}

# --- 1. rule 2's deny is a skuid RANGE over every uid (defects 1 and 3) ------

run=$(render single 192.0.2.10)
nft="$run/cogworx-floor.nft"
if [ ! -s "$nft" ]; then
	bad "no ruleset was rendered at all: $(cat "$ROOT/single.out")"
else
	# DEFECT 1. A deny with NO skuid match is one that opens with `ip daddr`
	# instead of `meta skuid`. It matches kernel-generated packets, which is
	# what killed the same-host return path.
	if grep -qE '^[[:space:]]*ip daddr .*drop' "$nft"; then
		bad "rule 2 rendered a drop with no skuid match; same-host return packets (no skuid) would be swallowed: $(grep -E '^[[:space:]]*ip daddr .*drop' "$nft")"
	else
		ok "no drop without a skuid match is rendered"
	fi
	# Every self-address deny carries a skuid expression -- the property that
	# makes socket-less kernel packets BREAK past it. Stated separately from the
	# exact-form check below so a future re-rendering that keeps the property
	# but changes the spelling still reports which half moved.
	while IFS= read -r line; do
		case "$line" in
			*'meta skuid '*) ;;
			*) bad "a rule2-self deny carries no skuid selector: $line" ;;
		esac
	done < <(grep -F 'cogworx-floor-rule2-self' "$nft")
	# DEFECT 4, stated separately from the exact form for the same reason: every
	# self-address deny is scoped to the ORIGINAL direction of a flow. Without
	# it the rule also matches the SYN-ACK a real listener sends back -- daddr is
	# the VM's own address on both ends of a same-host flow, and the reply's
	# dport is the client's ephemeral port, so no dport accept can save it. The
	# skuid selector above does NOT cover this: passt's forward listener is
	# created pre-drop, so its reply has a real owning socket and no NFT_BREAK.
	while IFS= read -r line; do
		case "$line" in
			*'ct direction original'*) ;;
			*) bad "a rule2-self deny is not scoped to the original direction; a real listener's reply would be swallowed and cogbox ssh dies: $line" ;;
		esac
	done < <(grep -F 'cogworx-floor-rule2-self' "$nft")
	# DEFECT 3. The skuid expression is a RANGE over every real uid.
	# 4294967295 is (uid_t)-1, the "no uid" sentinel and never a real account,
	# so 0-4294967294 is every uid that can own a socket -- `nixbld*`, `nobody`,
	# root, and anything added later.
	if grep -qF 'meta skuid 0-4294967294 ct direction original ip daddr 192.0.2.10 counter drop' "$nft"; then
		ok "rule 2 denies the VM's own address from every uid, as a skuid range"
	else
		bad "rule 2's deny is not the every-uid range form; ruleset: $(cat "$nft")"
	fi
	# ...and the enumeration is GONE. A named-uid deny satisfies every
	# skuid-match assertion above it -- it has a skuid selector, it is not a
	# matchless drop, it sits below the exception -- while leaving root-run and
	# `nixbld*` plugin builds and passt's pre-drop sockets outside rule 2. This
	# case names that silent revert rather than reporting it as a shape change.
	if grep -F 'cogworx-floor-rule2-self' "$nft" | grep -qF 'meta skuid "'; then
		bad "rule 2's deny is narrowed to named uid(s): $(grep -F 'cogworx-floor-rule2-self' "$nft" | grep -F 'meta skuid "')"
	else
		ok "no enumerated per-uid self-address deny is rendered"
	fi
	# The exception survives, and survives ABOVE the deny. Below it, it would be
	# dead -- and unlike under a narrowed deny it is not redundant: the control
	# uid is inside the range, so this accept is the only thing keeping
	# `cogbox ssh` (and Terminal) alive.
	acc=$(grep -nF 'cogworx-floor-rule2-control-ssh' "$nft" | head -1 | cut -d: -f1)
	den=$(grep -nF 'cogworx-floor-rule2-self' "$nft" | head -1 | cut -d: -f1)
	if [ -n "$acc" ] && [ -n "$den" ] && [ "$acc" -lt "$den" ]; then
		ok "the control-uid exception is rendered above the denies"
	else
		bad "the control-uid exception is missing or below the denies (accept line '$acc', deny line '$den')"
	fi
	if grep -qF 'meta skuid "root" ip daddr 192.0.2.10 tcp dport 2222-2237 counter accept' "$nft"; then
		ok "the exception is scoped to the control uid and to the guest SSH forward RANGE"
	else
		bad "the control-uid exception is not the expected uid/port-range shape: $(grep -F control-ssh "$nft")"
	fi
	# Rule 1 is untouched by this change: still uid-scoped, still the WHOLE
	# link-local range rather than an enumeration of ports.
	if grep -qF 'meta skuid "cogbox-passt" ip daddr 169.254.0.0/16 counter drop' "$nft"; then
		ok "rule 1 still denies the whole link-local range for the passt uid"
	else
		bad "rule 1 is not the expected shape: $(grep -F rule1 "$nft")"
	fi
	# Loopback is deliberately OUT of RULE 2, and both halves of that sentence are
	# asserted, because the failure modes are opposite. A rule-2 line naming
	# loopback would cut the L7 remap funnel AND the trusted half's own internal
	# traffic (rule 2 covers every uid). A floor with no loopback rule at all is
	# defect 5: the guest->loopback path resting on passt's tap-ingress filter and
	# --no-map-gw with nothing behind them.
	if grep -F 'cogworx-floor-rule2' "$nft" | grep -qF '127.'; then
		bad "rule 2 names loopback; the funnel and the trusted half's own loopback traffic would break: $(grep -F 'cogworx-floor-rule2' "$nft" | grep -F '127.')"
	else
		ok "rule 2 does not name loopback"
	fi

	# --- RULE 3, the loopback leg (defect 5) ---------------------------------
	#
	# The passt uid, and ONLY the passt uid, may not open a flow to loopback.
	# passt is the only process on the VM that turns guest bytes into host
	# sockets, and its per-flow outbound sockets are created after the privilege
	# drop, so it is both the necessary and the sufficient selector.
	if grep -qF 'meta skuid "cogbox-passt" ct direction original ip daddr 127.0.0.0/8 counter drop comment "cogworx-floor-rule3-loopback"' "$nft"; then
		ok "rule 3 denies the passt uid the whole of loopback, in the original direction only"
	else
		bad "rule 3's loopback deny is not the expected shape: $(grep -F 'cogworx-floor-rule3' "$nft")"
	fi
	# The one place a skuid RANGE is wrong. Rule 2 must be a range and rule 3
	# must not: l7proxy dials the mitm hop over loopback, mitmproxy dials its
	# upstreams, sshd and the nix daemon live there too. A range here is a VM
	# that cannot run its own enforcement stack.
	if grep -F 'cogworx-floor-rule3' "$nft" | grep -qF 'meta skuid 0-4294967294'; then
		bad "rule 3 is rendered as an every-uid range; the trusted half's own loopback traffic would be cut: $(grep -F 'cogworx-floor-rule3' "$nft" | grep -F '0-4294967294')"
	else
		ok "rule 3 stays scoped to the passt uid rather than the every-uid range"
	fi
	# The v6 mirror. Free today (the sandbox subnet is IPv4-only, and passt
	# enables v6 only with a v6 route) and it closes the half that would open
	# silently if the shared subnet were ever flipped to dual-stack.
	if grep -qF 'ip6 daddr ::1 counter drop comment "cogworx-floor-rule3-loopback6"' "$nft"; then
		ok "rule 3 mirrors the deny onto ::1"
	else
		bad "rule 3 has no v6 loopback mirror: $(grep -F 'cogworx-floor-rule3' "$nft")"
	fi
	# The exception, and its ORDER. Below the deny it is dead and the funnel is
	# dead with it -- the exact "secure and unusable" outcome section 5's live
	# case exists to catch.
	fac=$(grep -nF 'cogworx-floor-rule3-l7-funnel' "$nft" | head -1 | cut -d: -f1)
	fdn=$(grep -nF 'cogworx-floor-rule3-loopback"' "$nft" | head -1 | cut -d: -f1)
	if [ -n "$fac" ] && [ -n "$fdn" ] && [ "$fac" -lt "$fdn" ]; then
		ok "the L7 funnel exception is rendered above rule 3's deny"
	else
		bad "the funnel exception is missing or below rule 3's deny (accept line '$fac', deny line '$fdn')"
	fi
	# It admits the funnel's OWN targets and nothing else on loopback. 18443 and
	# 18444 are the TLS and HTTP funnel targets of the first triple (the
	# cogworx.gce.l7PortBase default the installer is rendered from) and 18446 is
	# the first port of the next triple cogbox slides onto; 18445 and 18448 are
	# those triples' mitmproxy SOCKS5 hops, which l7proxy dials under the PROXY
	# uid and passt must never reach. A port RANGE instead of a set would admit
	# them and pass every other assertion here.
	fline=$(grep -F 'cogworx-floor-rule3-l7-funnel' "$nft")
	fset=$(printf '%s' "$fline" | sed -e 's/.*dport { //' -e 's/ }.*//')
	# Checked before the membership tests below, so a shape change reports itself
	# as a shape change rather than as a missing port: a `dport <lo>-<hi>` range
	# is the tempting simplification here and it is the one that quietly re-admits
	# every triple's mitm hop.
	case "$fline" in
		*'dport { '*' }'*) ok "the funnel exception is an explicit port set, not a range" ;;
		*) bad "the funnel exception is not a port set; a range cannot skip every third port and would admit the mitm hops: $fline" ;;
	esac
	for p in 18443 18444 18446; do
		case ", $fset," in
			*", $p,"*) ok "the funnel exception admits the funnel target $p" ;;
			*) bad "the funnel exception omits the funnel target $p; the L7 funnel would be dropped: $fset" ;;
		esac
	done
	for p in 18445 18448; do
		case ", $fset," in
			*", $p,"*) bad "the funnel exception admits $p, a mitmproxy SOCKS5 hop; a guest reaching it holds the terminate tier's raw upstream with no vetting: $fset" ;;
			*) ok "the funnel exception excludes the mitm hop $p" ;;
		esac
	done

	# --- rule 3's OTHER exception, and the CAP on the whole allow-list --------
	#
	# The host's own DNS forwarder is the only socket outside the funnel targets
	# the passt uid may open on loopback. It is there because guest/host
	# resolution parity has no shape that leaves rule 1 alone: passt re-emits the
	# guest's intercepted DNS queries under the PASST uid, so a forwarding target
	# of 169.254.169.254 is indistinguishable at nftables from the guest dialling
	# the metadata API and rule 1 correctly drops it. Aiming those queries at a
	# root-run loopback forwarder is what keeps rule 1 completely untouched.
	#
	# THE CAP IS THE POINT of this block, not the presence check. Rule 3's accept
	# set must be the funnel ports PLUS this one socket and nothing else, and two
	# widenings pass every assertion above while failing only here: an extra
	# accept line (127.0.0.1:53 "for DNS" is the obvious one, and it would put
	# the mitm hop's own address back in the allow-list's company), and a
	# broadened address or port on this pair.
	dline=$(grep -F 'cogworx-floor-rule3-dns-forwarder' "$nft")
	nd=$(grep -cF 'cogworx-floor-rule3-dns-forwarder' "$nft")
	if [ "$nd" = 2 ]; then
		ok "the DNS-forwarder exception is exactly two rules (one udp, one tcp)"
	else
		bad "expected exactly 2 DNS-forwarder accepts (udp + tcp), got $nd: $dline"
	fi
	for proto in udp tcp; do
		want="meta skuid \"cogbox-passt\" ct direction original ip daddr 127.0.0.53 $proto dport 53 counter accept"
		if grep -qF "$want" "$nft"; then
			ok "the DNS-forwarder exception admits exactly 127.0.0.53:53/$proto for the passt uid"
		else
			bad "no exact $proto DNS-forwarder accept; a widened address or port would still satisfy a substring check: $dline"
		fi
	done
	# Address- and port-scoped, both stated as REFUSALS so a widening reports
	# itself as one. A prefix here would be a loopback carve-out; a port range
	# would re-admit the mitm hop by another door.
	case "$dline" in
		*'127.0.0.53/'*|*'127.0.0.0/8'*) bad "the DNS-forwarder exception carries a prefix; it must name one address: $dline" ;;
		*) ok "the DNS-forwarder exception names a single address, not a prefix" ;;
	esac
	case "$dline" in
		*'dport {'*|*'dport 53-'*) bad "the DNS-forwarder exception carries a port range or set; it must name one port: $dline" ;;
		*) ok "the DNS-forwarder exception names a single port, not a range or set" ;;
	esac
	# Ordered above the deny, like the funnel exception. Below it, guest DNS is
	# dropped and every sandbox on this VM resolves nothing.
	dacl=$(grep -nF 'cogworx-floor-rule3-dns-forwarder' "$nft" | head -1 | cut -d: -f1)
	if [ -n "$dacl" ] && [ -n "$fdn" ] && [ "$dacl" -lt "$fdn" ]; then
		ok "the DNS-forwarder exception is rendered above rule 3's deny"
	else
		bad "the DNS-forwarder exception is missing or below rule 3's deny (accept line '$dacl', deny line '$fdn')"
	fi
	# THE CAP. Every rule-3 line is one of: the funnel accept, the two
	# DNS-forwarder accepts, the v4 loopback deny, the v6 loopback deny. Five,
	# exactly. A sixth is a widening this file has no other way to see.
	n3=$(grep -cF 'cogworx-floor-rule3' "$nft")
	if [ "$n3" = 5 ]; then
		ok "rule 3 is exactly five lines: the funnel accept, the DNS-forwarder pair, and the two loopback denies"
	else
		bad "rule 3 rendered $n3 lines, expected 5; an added accept widens the passt uid's loopback reach: $(grep -F 'cogworx-floor-rule3' "$nft")"
	fi
	# ...and no rule-3 accept names any other loopback target. 127.0.0.1 belongs
	# to the funnel line alone (whose port set is checked above); anything else
	# on 127/8 is a new hole wearing a rule-3 comment.
	while IFS= read -r line; do
		case "$line" in
			*accept*)
				case "$line" in
					*'ip daddr 127.0.0.1 '*|*'ip daddr 127.0.0.53 '*) ;;
					*) bad "a rule-3 accept names an unexpected loopback target: $line" ;;
				esac
				;;
		esac
	done < <(grep -F 'cogworx-floor-rule3' "$nft")
fi

# --- 2. every address gets a deny, and a CIDR is never loaded verbatim -------
#
# A prefix loaded as written would turn "the VM itself" into "the whole sandbox
# subnet" -- an availability outage dressed as a security rule.

run=$(render multi '192.0.2.10/24, 192.0.2.11')
nft="$run/cogworx-floor.nft"
if grep -qF '/24' "$nft"; then
	bad "a prefix length reached the ruleset; rule 2 would cover the whole subnet: $(grep -F /24 "$nft")"
else
	ok "the prefix length is stripped before the address reaches nft"
fi
for a in 192.0.2.10 192.0.2.11; do
	if grep -qF "meta skuid 0-4294967294 ct direction original ip daddr $a counter drop" "$nft"; then
		ok "every address gets the every-uid range deny ($a)"
	else
		bad "no every-uid range deny for $a: $(cat "$nft")"
	fi
done
# One rule per address and no more: an extra rule2-self line means a second,
# narrower statement of the same policy has been added beside the range one,
# and two mechanisms for one policy can disagree.
n=$(grep -cF 'cogworx-floor-rule2-self' "$nft")
if [ "$n" = 2 ]; then
	ok "two addresses render exactly two self-address denies (one range rule each)"
else
	bad "expected 2 self-address denies for 2 addresses, got $n: $(cat "$nft")"
fi

# --- 3. an empty address set still fails the boot closed ---------------------
#
# A rule 2 rendered from no addresses is VACUOUS, and a shape-only check passes
# it. The supervisor Requires= a unit that SUCCEEDED, so a vacuous pass would
# start a sandbox behind a floor enforcing nothing.

run=$(render empty '')
nft="$run/cogworx-floor.nft"
if grep -qF 'cogworx-floor-rule2-self' "$nft"; then
	bad "an empty address set still rendered a rule-2 deny: $(cat "$nft")"
else
	ok "an empty address set renders no rule-2 deny (which is why the verifier must refuse the boot)"
fi
out=$(COGWORX_RUN_DIR="$run" "$VERIFY" 2>&1); rc=$?
case "$out" in
	*'Refusing the boot'*) ;;
	*) bad "the verifier did not name the empty-set refusal: $out" ;;
esac
if [ "$rc" != 0 ]; then
	ok "an empty address set exits the verifier non-zero, so the supervisor never starts"
else
	bad "the verifier accepted an empty address set (rc=$rc)"
fi

run=$(render absent ABSENT)
out=$(COGWORX_RUN_DIR="$run" "$VERIFY" 2>&1); rc=$?
if [ "$rc" != 0 ]; then
	ok "an absent cogworx-self-addrs with no provider fallback also exits non-zero"
else
	bad "the verifier accepted an absent cogworx-self-addrs (rc=$rc)"
fi

# --- 4. PROBE POLARITY (defect 2) -------------------------------------------
#
# This case runs the verifier for real against a self address of 127.0.0.1 with
# NO floor loaded and nothing listening. Every probe therefore classifies as
# `refused` -- immediately, never a timeout -- which is precisely the pair of
# polarities under test:
#
#   - the three DENY probes must FAIL on `refused`. This is the floorless VM.
#     A deny probe that passed here would be a catastrophic regression: the
#     unit would go green on a machine with no enforcement at all.
#   - the control-uid EXCEPTION probe must PASS on `refused`. At floor time
#     passt is not running (the supervisor Requires= this unit and starts passt
#     afterwards), so nothing can be listening on the guest SSH forward and RST
#     is the only honest answer a healthy VM can give. A probe demanding a
#     completed connection would fail every boot of a correct image, and the
#     obvious "remedy" for that is to widen rule 2 -- the exact pressure the
#     probe exists to resist.
#
# Probe 5 also runs here and is deliberately NOT asserted on: it binds its own
# listener on 127.0.0.1 and its outcome depends on whether this process can
# setpriv, which is a property of the test host and not of the floor. Its
# behaviour is section 5's business.

run="$ROOT/polarity/run"
mkdir -p "$run"
printf '127.0.0.1\n' > "$run/cogworx-self-addrs"
out=$(COGWORX_RUN_DIR="$run" "$VERIFY" 2>&1); rc=$?
for what in 'rule 1, metadata API' 'rule 2, passt leg' 'rule 2, proxy leg'; do
	case "$out" in
		*"PROBE FAILED: $what"*) ok "a non-dropped '$what' fails the boot" ;;
		*) bad "'$what' did not fail on a floorless machine; probe polarity inverted. Output: $out" ;;
	esac
done
case "$out" in
	*'PROBE FAILED: rule 2 control-uid exception'*)
		bad "the control-uid exception probe failed on a REFUSED connect; it demands a listener that cannot exist before the supervisor starts passt. Output: $out" ;;
	*) ok "a refused (not dropped) control-uid connect passes the exception probe" ;;
esac
if [ "$rc" != 0 ]; then
	ok "a floorless machine exits the verifier non-zero"
else
	bad "the verifier passed on a machine with no floor loaded at all (rc=$rc)"
fi

# --- 5. THE LIVE CASE, WITH A REAL LISTENER (defect 4) -----------------------
#
# Sections 1-4 read a rendered file and run probes against no ruleset at all.
# That is exactly the blind spot defect 4 shipped through: the rule was the
# right SHAPE by every assertion above it, and the packets still did the wrong
# thing. So this section loads the REAL rendered ruleset into a throwaway
# user+network namespace -- the host's ruleset is never touched, and nothing
# here needs root -- puts a REAL listener on an exempt port (the production
# probe 5 binds it), and asserts on
# completed connections rather than on text.
#
# It is a SKIP, not a failure, where a kernel with nftables + conntrack or
# unprivileged user namespaces is unavailable: the assertions in sections 1-4
# pin the rule's shape everywhere, and this section adds the behaviour where the
# platform can show it. A skip is printed loudly so it cannot be mistaken for a
# pass.

run=$(render live 192.0.2.10)
if ! command -v unshare >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
	echo "skip - live netfilter case: unshare/nft/ip not all available"
else
	live_out=$(unshare -Urn "$BASH" "$0" --live-child "$VERIFY" "$run" 2>&1); live_rc=$?
	printf '%s\n' "$live_out"
	case "$live_out" in
		*LIVE-BEGIN*) ;;
		*) live_rc=77; echo "skip - live netfilter case: could not enter a user+network namespace" ;;
	esac
	if [ "$live_rc" = 77 ]; then
		echo "skip - live netfilter case skipped (see above); rule shape is still pinned by sections 1-2"
	elif [ "$live_rc" != 0 ]; then
		n=$(printf '%s\n' "$live_out" | grep -c '^FAIL - ')
		[ "$n" -gt 0 ] || n=1
		fails=$((fails + n))
	fi
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all floor checks passed"
