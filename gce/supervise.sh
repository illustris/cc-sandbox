#!/usr/bin/env bash
# cogworx-supervisor: the GCE transcription of the cogsmos k8s sandbox
# entrypoint, with the legs a GCE VM needs and the k8s pod does not.
#
# Leg map, so a reader can line this up against the pod args. The order below is
# the order the code runs in; keep it synchronized with the implementation:
#   a   read the per-start readiness nonce from instance metadata, ONCE
#   a2  publish the VM's own host key as a guest attribute, stamped with (a),
#       on EVERY boot class and BEFORE both short-circuits
#   d1  resolver short-circuit: never start the sandbox, and never touch the
#       state disk or cogbox -- a throwaway resolver has neither and seeds its
#       own placeholder config over SSH
#   b   cogbox init, sized and moded from instance metadata, after the
#       preconditions it consumes (state-disk mount, self addresses, host
#       resolver). BEFORE (d2): a maintenance boot exists precisely so a
#       mutation can run against a STOPPED instance, and a mutation needs a
#       config.json to mutate. Initializing is host-half work, not starting.
#   d2  maintenance short-circuit: initialized, but the sandbox guest is
#       deliberately never started
#   c   stage the gateway SSH CA + principal before the guest boots
#   e   wipe the stale runtime dir and lock
#   f   cogbox start --no-ssh
#   g   (moved out) the cogbox.log tail lives in cogworx-cogbox-log.service
#   h   publish readiness once the GUEST's host key file appears
#   i   hold the unit open for the sandbox's lifetime
#   j   delete readiness FIRST, then exit non-zero so Restart=always re-runs
#
# Serial discipline: this script's stdout and stderr go to the
# JOURNAL. Only classified boot/lifecycle lines reach serial, and only through
# emit(). Nothing here inherits a file descriptor pointing at the serial port,
# because on GCE serial output is provider-retained state outside the VM
# boundary, readable under a coarser grant than the control channel -- and
# cogbox.log carries l7proxy's per-request allow/deny decisions and the
# mitmproxy credential-injection addon's output.

set -uo pipefail

MD="${COGWORX_MD_BASE:-http://metadata.google.internal/computeMetadata/v1}"
GA="$MD/instance/guest-attributes"
MDHDR='Metadata-Flavor: Google'
SERIAL="${COGWORX_SERIAL:-/dev/ttyS0}"
STATE_DIR="${COGWORX_STATE_DIR:-/var/lib/cogbox-state}"
# Test seam only, matching COGWORX_MD_BASE; the unit starts from a clean
# environment so this is never set in production.
RESOLV_CONF="${COGWORX_RESOLV_CONF:-/etc/resolv.conf}"
VM_HOSTKEY_PUB="$STATE_DIR/sshd/ssh_host_ed25519_key.pub"
POLL_INTERVAL="${COGWORX_POLL_INTERVAL:-5}"
READY_TIMEOUT="${COGWORX_READY_TIMEOUT:-300}"
HOSTKEY_TIMEOUT="${COGWORX_HOSTKEY_TIMEOUT:-60}"

# Classified serial writer. Everything else in this script -- and every child
# it spawns -- writes to the journal.
emit() { printf 'cogworx: %s\n' "$*" >>"$SERIAL" 2>/dev/null || true; }
note() { printf 'cogworx-supervisor: %s\n' "$*"; }
fatal() {
	note "$*"
	emit "FAILED: $*"
	exit 1
}

md_get() { curl -fsS -H "$MDHDR" --max-time 10 "$MD/instance/attributes/$1" 2>/dev/null; }
# An arbitrary instance-metadata path, for the provider's own facts (as opposed
# to the control plane's attributes).
md_path() { curl -fsS -H "$MDHDR" --max-time 10 "$MD/$1" 2>/dev/null; }
# Key PRESENCE, never value: the control plane clears a flag by REMOVING the
# item, so a value test would read a cleared "false" as still set.
md_has() { curl -fsS -o /dev/null -H "$MDHDR" --max-time 10 "$MD/instance/attributes/$1" 2>/dev/null; }
ga_put() { curl -fsS -o /dev/null -X PUT --data-binary "$2" -H "$MDHDR" --max-time 10 "$GA/$1" 2>/dev/null; }
ga_del() { curl -fsS -o /dev/null -X DELETE -H "$MDHDR" --max-time 10 "$GA/$1" 2>/dev/null; }

# --- (a) the per-start nonce, read exactly once per boot --------------------
#
# GCE hands Status nothing boot-shaped to compare against, so freshness rides a
# token cogworxd controls end to end. Re-reading it later in the boot would
# defeat the point: the whole guarantee is that ONE value is stamped onto every
# attribute this boot publishes.
NONCE="$(md_get cogworx-start-nonce)"
[ -n "$NONCE" ] || fatal "no cogworx-start-nonce in instance metadata; readiness could never be bound to this start epoch"

# --- (a2) publish the VM host key, before anything else ---------------------
#
# On EVERY boot class -- fresh, maintenance, resolver, provider-driven restart
# -- and BEFORE both the (d1) and (d2) short-circuits. Publishing this later, or
# only on boots that start a sandbox, kills two paths outright: an instance whose
# first-ever boot is a MAINTENANCE boot could never be pinned (so every stopped
# mutation would return ErrSandboxNotReady forever), and the resolver flow would
# block on an attribute that never appears -- whose cheapest "fix" is a TOFU
# dial on the one connection that carries a live git OAuth token.
hostkey_deadline=$(( HOSTKEY_TIMEOUT / POLL_INTERVAL + 1 ))
while [ ! -s "$VM_HOSTKEY_PUB" ] && [ "$hostkey_deadline" -gt 0 ]; do
	hostkey_deadline=$(( hostkey_deadline - 1 ))
	sleep "$POLL_INTERVAL"
done
[ -s "$VM_HOSTKEY_PUB" ] || fatal "sshd host key $VM_HOSTKEY_PUB never appeared; refusing to boot a sandbox that cogworxd could only reach by TOFU"
# Publish type+base64 only: the trailing comment is host-local noise the
# control plane must not have to normalize away before comparing a pin.
HOSTKEY_LINE="$(awk '{print $1" "$2; exit}' "$VM_HOSTKEY_PUB")"
if ga_put cogworx/vm-host-key "$NONCE $HOSTKEY_LINE"; then
	emit "vm host key published"
else
	fatal "could not publish the cogworx/vm-host-key guest attribute"
fi

# --- instance shape, all from metadata --------------------------------------
INSTANCE="$(md_get cogworx-instance)"
[ -n "$INSTANCE" ] || fatal "no cogworx-instance in instance metadata"
VCPU="$(md_get cogworx-vcpu)"
MEMMB="$(md_get cogworx-mem-mb)"
NETWORK="$(md_get cogworx-network)"
GUEST_RESOLVER="$(md_get cogworx-guest-resolver)"
SELF_ADDRS_RAW="$(md_get cogworx-self-addrs)"

# The maintenance flag, read ONCE into a variable because it is now consulted
# TWICE: by (b) below, to decide whether an already-initialized instance needs
# init re-run, and by the (d2) short-circuit past it. One read means a boot
# cannot observe the flag SET at (b) and CLEAR at (d2) and go on to start a
# guest inside a maintenance round trip the control plane still believes it
# owns. Presence, never value: the control plane clears the flag by REMOVING the
# item (md_has).
MAINTENANCE=0
md_has cogworx-maintenance && MAINTENANCE=1

# --- (d1) resolver short-circuit --------------------------------------------
#
# Checked AFTER (a2) and BEFORE everything that touches the state disk or
# cogbox, which is the opposite placement from (d2) and for a concrete reason: a
# resolver VM is this same image booted with NO state disk
# attached, and it seeds its own placeholder config over the control channel
# (`cogbox init -y -n template`) once cogworxd has pinned its host key. Running
# the init below on
# a resolver boot would either trip the state-disk assertion and turn a
# throwaway VM into a restart loop, or write cogbox state onto the boot disk of
# a machine whose whole job is to evaluate an attacker-controlled flake. It
# needs less setup than a sandbox, not more.
#
# Held open with `sleep infinity` rather than returned from: the unit is
# Restart=always, so a plain return hot-loops -- systemd restarts the script,
# ExecStopPost fires on every cycle, and a short-circuited boot becomes a
# restart storm.
if md_has cogworx-resolver; then
	ga_del cogworx/ready || true
	emit "resolver boot: sandbox deliberately not started"
	note "cogworx-resolver is set; holding the host half up with no sandbox"
	exec sleep infinity
fi

# Past this point the boot will WRITE COGBOX STATE, so the state disk is not
# optional: config.json, the per-instance L7 CA, the secret store and the
# guest's host key all live on it. This covers a maintenance boot too, and there
# it is the load-bearing case: seeding config.json onto an unmounted mount point
# puts it on the boot disk, where the mount that arrives later hides it and the
# mutation the maintenance boot exists to serve is silently written to state
# nothing will ever read. Only a resolver boot legitimately has no state disk,
# and it returned above -- which is why this is asserted here rather than as a
# unit-level Requires= on the mount.
if ! mountpoint -q "$STATE_DIR"; then
	fatal "$STATE_DIR is not a mount point; refusing to write cogbox state whose CA and secret store would land on the boot disk"
fi

# --- self addresses: the same two sources the floor unit uses ---------------
#
# cogworx-self-addrs is authoritative when it carries anything, but it is EMPTY
# on a first boot: the control plane stamps it into the insert body before any
# address has been allocated, and only a later Start refreshes it. Fall back to
# the provider's own statement of this VM's interface addresses, exactly as
# gce/floor.nix does for rule 2. Both empty is still fatal.
if [ -z "${SELF_ADDRS_RAW//[[:space:]]/}" ]; then
	_nics="$(md_path 'instance/network-interfaces/')"
	read -r -a _nic_toks <<< "$(printf '%s' "$_nics" | tr ',\n\t' '   ')"
	for _nic in ${_nic_toks[@]+"${_nic_toks[@]}"}; do
		SELF_ADDRS_RAW="$SELF_ADDRS_RAW $(md_path "instance/network-interfaces/${_nic%/}/ip")"
	done
fi

read -r -a _self_toks <<< "$(printf '%s' "$SELF_ADDRS_RAW" | tr ',\n\t' '   ')"
SELF_CIDRS=()
BIND_ADDR=""
for tok in ${_self_toks[@]+"${_self_toks[@]}"}; do
	bare="${tok%%/*}"
	[ -n "$bare" ] || continue
	if [ -z "$BIND_ADDR" ]; then BIND_ADDR="$bare"; fi
	case "$tok" in
		*/*) SELF_CIDRS+=("$tok") ;;
		*) SELF_CIDRS+=("$bare/32") ;;
	esac
done
if [ "${#SELF_CIDRS[@]}" -eq 0 ]; then
	fatal "neither cogworx-self-addrs nor the metadata server named an address for this vm; without one bindAddr defaults to loopback and the l7proxy self-address floor is never seeded"
fi

# --- COGBOX_HOST_RESOLVER: the one guest-DNS half `cogbox init` consumes -----
#
# It becomes `cogbox init --dns-host` below, so it has to be in hand BEFORE the
# init. Its two siblings -- the guest-resolver attribute and the resolv.conf
# precondition -- are consumed by passt when the GUEST starts, so they are
# asserted past the (d2) short-circuit instead; the narrative for all three
# lives there.
[ -n "${COGBOX_HOST_RESOLVER:-}" ] || fatal "COGBOX_HOST_RESOLVER is unset; passt would have no forwarding target for the guest's DNS and the L4 shim would drop the query it re-emits"

# --- (b) cogbox init --------------------------------------------------------
#
# BEFORE the (d2) maintenance short-circuit. Maintenance mutations read and
# rewrite config.json, which lives on the state disk and is created only by this
# leg. Initialization is required even when the guest remains stopped.
#
# --bind-addr is the VM's non-loopback address; without it bindAddr stays
# 127.0.0.1 and remote forwarding cannot rely on the configured address.
#
# --no-implicit-dns is passed unconditionally on this backend: cogbox's shared
# filter otherwise allows ANY port-53 destination before the deny walk, so a
# rules-mode sandbox with zero allow rules would retain arbitrary-destination
# DNS -- a tunnel that escapes the seeded link-local deny, every RFC1918 deny,
# and the IPv6 fail-close alike.
#
# --dns-host is its inseparable other half; see the guest-DNS block past (d2).
#
# --self-addr feeds l7proxy's hard floor, so the relay refusal does not
# rest on nftables alone.
#
# WHY A MAINTENANCE BOOT ONLY SEEDS WHAT IS MISSING. Re-running init is SAFE:
# cogbox-launch.sh writes config.json, the scaffold flake, authorized_keys and
# every harness default only when the file is absent, so an already-initialized
# instance keeps its plugins, its L4/L7 rules, its secret bindings and its
# harness overlay verbatim. It is not FREE, though -- once config.json lists a
# plugin, init's tail re-execs a full nix eval of the composed runner, minutes
# on a cold store -- and cogworxd's maintenance path deliberately does not pay
# that cost per mutation. A maintenance boot therefore runs init only when there
# is no config.json to mutate, which is exactly the first-boot hole above; a
# normal boot still runs it unconditionally, as it always has, so its self-heal
# for a deleted authorized_keys or harness path is untouched.
#
# CHECKED, not bare-dereferenced, because this line is now on the path of EVERY
# boot class and both ways the variable can go missing fail badly. UNSET kills the
# shell under `set -u` with "unbound variable" on stderr -- which goes to the
# JOURNAL, not to serial, so the boot emits nothing classified and is
# undiagnosable from getSerialPortOutput, the only channel available on a box that
# never came up. EMPTY does not trip `set -u` at all: init would seed
# /cogbox/instances/... on the boot disk, and the mutation this boot exists for
# would read a config that is not the instance's. The unit sets it
# (gce/supervisor.nix), so this is a guard against a future env change rather than
# a reachable state; fatal() gives it the classified serial line, and the :? below
# keeps a bare dereference from ever being the failure mode again.
[ -n "${XDG_CONFIG_HOME:-}" ] || fatal "XDG_CONFIG_HOME is unset or empty; cogbox's instance config root would be / and this boot could neither find nor seed the instance's config.json"
INSTANCE_CONFIG="${XDG_CONFIG_HOME:?}/cogbox/instances/$INSTANCE/config.json"
if [ "$MAINTENANCE" -eq 1 ] && [ -f "$INSTANCE_CONFIG" ]; then
	note "cogworx-maintenance is set and $INSTANCE is already initialized; not re-running cogbox init"
else
	init_args=(init -y -n "$INSTANCE")
	[ -n "$VCPU" ] && init_args+=(--vcpu "$VCPU")
	[ -n "$MEMMB" ] && init_args+=(--mem "$MEMMB")
	[ -n "$NETWORK" ] && init_args+=(--network "$NETWORK")
	init_args+=(--bind-addr "$BIND_ADDR" --no-implicit-dns --dns-host "$COGBOX_HOST_RESOLVER")
	for cidr in "${SELF_CIDRS[@]}"; do
		init_args+=(--self-addr "$cidr")
	done
	emit "initializing instance $INSTANCE"
	cogbox "${init_args[@]}" || fatal "cogbox init failed"
fi

# --- (d2) maintenance short-circuit -----------------------------------------
#
# Past (b) on purpose, and that is the whole fix: the host half is up AND cogbox
# is initialized, so the mutation cogworxd is about to run over SSH has a
# config.json to read. The sandbox GUEST is still never started, which is the
# only property required of this leg. Held open with `sleep infinity` for the
# reason spelled out at (d1).
if [ "$MAINTENANCE" -eq 1 ]; then
	ga_del cogworx/ready || true
	emit "maintenance boot: sandbox deliberately not started"
	note "cogworx-maintenance is set; holding the host half up with no sandbox"
	exec sleep infinity
fi

# --- guest DNS: the two halves passt consumes when the GUEST starts ----------
#
# Asserted past (d2) on purpose. Both are preconditions for passt's DHCP offer
# to the guest, and a maintenance boot has no guest -- so checking them earlier
# would let a resolv.conf race (systemd-resolved up, its file not yet written)
# refuse a boot whose only job is to hold the host half up for one mutation, and
# refuse it BEFORE the init above, which is the very shape of the bug this file
# was reordered to fix. A normal boot still asserts both before `cogbox start`.
#
# The guest must resolve names the way the HOST does, so an internal name
# resolves to its internal address -- the parity the local and k8s backends get
# for free. It cannot inherit the host's resolver here: on GCE that is the VPC
# resolver at the metadata address, which floor rule 1 denies the passt uid
# wholesale. So:
#
#   COGBOX_GUEST_RESOLVER  -> passt --dns-forward <addr> AND --no-map-gw. The
#     address is a HANDLE, not a destination: passt intercepts the guest's
#     queries to it at the tap and re-emits them host-side. It is never routed,
#     so it needs no routability and faces no L4 rule.
#   COGBOX_HOST_RESOLVER   -> passt --dns-host <addr>, the loopback forwarder
#     those re-emitted queries go to (systemd-resolved's stub). The forwarder
#     runs as ROOT and rule 1 matches only the passt uid, so IT may query the
#     VPC resolver while the guest cannot -- which is the whole point: rule 1 is
#     untouched and the guest still cannot reach link-local on any port.
#   --dns-host on `cogbox init` -> the L4 shim's matching seed. --no-implicit-dns
#     below puts loopback DNS back under the shim's loopback deny, and passt's
#     re-emitted query IS a loopback connect, so without this seed every
#     rules-mode guest on this VM has no DNS and nothing says so.
#
# Absence of the guest-resolver attribute is FATAL, the same fail-closed the
# self-addrs check above applies, and for a stronger reason than "no DNS":
# --no-map-gw travels with it, so an absent attribute would silently drop that
# flag from BOTH passt invocations. passt would then keep its default gateway
# mapping, which translates guest traffic to the gateway address into the host's
# loopback for all TCP and untracked UDP. In `rules` mode the L4 shim's loopback
# deny still catches that; `full` mode has no L4 filter at all, so a full-mode
# guest would reach the trusted half's own listeners -- the l7proxy triple and
# the mitm hop -- through the gateway address, exactly what the policy denies
# denied in EVERY mode. The control plane always stamps the attribute
# (COGWORX_GCP_GUEST_DNS_ADDR is a required knob), so an absent one is a broken
# provision, not a supported deployment.
[ -n "$GUEST_RESOLVER" ] || fatal "cogworx-guest-resolver is absent; --no-map-gw would not be applied and passt's gateway mapping would stay open in both modes"
export COGBOX_GUEST_RESOLVER="$GUEST_RESOLVER"

# THE PRECONDITION FOR THE ADVERTISEMENT, checked because its failure is
# silent. passt does not advertise its --dns-forward address unconditionally: it
# reads /etc/resolv.conf, and only when the nameserver it finds there is a
# LOOPBACK address does it substitute the --dns-forward address in the DHCP offer
# (passt conf.c add_dns_resolv4, the "--dns-forward and --no-map-gw" case). If
# resolv.conf still names the VPC resolver -- resolved not up yet, or an image
# built without it -- passt advertises 169.254.169.254 to the guest instead, rule
# 1 drops every query the guest then sends, and the sandbox comes up healthy with
# no DNS at all. Restart=always makes this self-heal if it is only a race.
if ! grep -Eq "^[[:space:]]*nameserver[[:space:]]+${COGBOX_HOST_RESOLVER}([[:space:]]|$)" "$RESOLV_CONF" 2>/dev/null; then
	fatal "$RESOLV_CONF does not name the host forwarder $COGBOX_HOST_RESOLVER; passt would advertise the host's real resolver to the guest and floor rule 1 would drop every query"
fi

# --- (c) stage the gateway user CA and this instance's principal ------------
#
# Public-key material and an instance id only; no secret. The guest's
# cogbox-vm-sshd-prep seeds empty fail-closed files when these are absent, so a
# deployment without the SSH gateway is not broken by their absence.
SSH_CA_PUB="$(md_get cogworx-ssh-ca-pub)"
SSH_PRINCIPAL="$(md_get cogworx-ssh-principal)"
if [ -n "$SSH_CA_PUB" ] && [ -n "$SSH_PRINCIPAL" ]; then
	_sd="$COGBOX_DATA/instances/$INSTANCE"
	mkdir -p "$_sd/.config/ssh-principals" "$_sd/ssh"
	printf '%s\n' "$SSH_CA_PUB" > "$_sd/.config/ssh-ca.pub"
	printf '%s\n' "$SSH_PRINCIPAL" > "$_sd/.config/ssh-principals/root"
fi

# The mitmproxy terminate tier runs under COGBOX_PROXY_RUNAS, so its persistent
# per-instance CA confdir has to be writable by that uid. cogbox init creates
# the instance config dir as root; hand the one subtree the dropped proxy owns
# over to it before the launch, or the L7 terminate tier fails to start and
# every terminate host is blocked.
if [ -n "${COGBOX_PROXY_RUNAS:-}" ]; then
	_icd="$XDG_CONFIG_HOME/cogbox/instances/$INSTANCE"
	mkdir -p "$_icd/l7-ca"
	chown -R "${COGBOX_PROXY_RUNAS}" "$_icd/l7-ca" 2>/dev/null \
		|| note "warning: could not chown $_icd/l7-ca to $COGBOX_PROXY_RUNAS"
	chmod 0750 "$_icd/l7-ca" 2>/dev/null || true
fi

# --- (e) wipe the stale runtime dir and lock --------------------------------
#
# Still required despite /run being a tmpfs on a full VM: a live pidfile with a
# recycled pid false-trips cogbox's "already running" guard and exits 75.
RT="$XDG_RUNTIME_DIR/cogbox-$INSTANCE"
rm -rf "$RT" "$RT.lock"

# --- (f) start the sandbox --------------------------------------------------
emit "starting sandbox $INSTANCE"
start_args=(start --no-ssh -y -n "$INSTANCE")
[ -n "$VCPU" ] && start_args+=(--vcpu "$VCPU")
[ -n "$MEMMB" ] && start_args+=(--mem "$MEMMB")
if ! cogbox "${start_args[@]}"; then
	emit "sandbox start failed"
	ga_del cogworx/ready || true
	exit 1
fi

# --- (h) + (i) readiness, then hold the unit open ---------------------------
#
# Readiness is the GUEST's persisted host key file appearing on the state disk
# -- the same signal the k8s startupProbe uses -- published as a guest attribute
# stamped with this boot's nonce. It is level-HELD, not latched: leg (j) below
# and ExecStopPost both delete it, so a dead sandbox cannot coast on a stamped
# attribute for the rest of the start epoch the way a one-shot stamp would let
# it. Timing budget mirrors the pod's initialDelay 10 + 5*60.
GUEST_KEY="$COGBOX_DATA/instances/$INSTANCE/ssh/ssh_host_ed25519_key.pub"
ready=0
iters_left=$(( READY_TIMEOUT / POLL_INTERVAL + 1 ))
sleep "$POLL_INTERVAL"
while :; do
	if ! cogbox status -n "$INSTANCE" >/dev/null 2>&1; then
		emit "sandbox exited"
		break
	fi
	if [ "$ready" -eq 0 ] && [ -s "$GUEST_KEY" ]; then
		if ga_put cogworx/ready "$NONCE ok"; then
			ready=1
			emit "sandbox ready"
		else
			note "warning: could not publish the readiness guest attribute; will retry"
		fi
	fi
	if [ "$ready" -eq 0 ]; then
		iters_left=$(( iters_left - 1 ))
		if [ "$iters_left" -le 0 ]; then
			emit "sandbox did not become ready within ${READY_TIMEOUT}s"
			break
		fi
	fi
	sleep "$POLL_INTERVAL"
done

# --- (j) unpublish, THEN fail so Restart=always re-runs the sequence --------
ga_del cogworx/ready || true
note "sandbox is no longer running; exiting so the unit restarts"
exit 1
