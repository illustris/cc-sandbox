# cogworx-floor.service -- the root-owned nftables floor, plus positive
# verification before any sandbox starts.
#
# Rule 1: everything from the passt uid to 169.254.0.0/16 is dropped. A
# WHOLESALE link-local deny, not a per-port enumeration. The two surfaces that
# make it load-bearing are tcp/80 (the metadata API -- denying it closes token
# access and, more importantly here, guest forgery of the guest attributes the
# boot path trusts) and 53 (on GCE the VPC resolver IS the metadata address
# and may resolve private DNS, so it could expose private names and addresses
# plus a DNS-tunnel egress path no filter sees). Enumerating only those two
# tuples would admit any
# future link-local listener by construction.
#
# Rule 1 stays scoped to the passt uid rather than becoming a default-deny, and
# the reason is not timidity: the trusted half's own traffic goes to that address
# too. Every unit on the boot path reads instance metadata there, whatever the
# DNS upstream is; and at the DEFAULT `vpcResolver` its own RESOLUTION goes there
# as well -- l7proxy's host-side re-resolution that all L7 policy depends on,
# mitmproxy upstreams, credential refresh, and nix substituters. Changing
# `vpcResolver` affects resolution but not metadata access or this rule's scope.
# In-VM builds run as nixbld* under the daemon, so no accept-list of named uids
# could have covered them either. Root-run builds retain a read channel to
# instance metadata and the configured resolver; that is outside this rule's
# scope.
#
# Rule 2: traffic to the VM's OWN non-loopback addresses is dropped from EVERY
# uid -- written as a skuid RANGE spanning every real uid, not as an enumeration
# of names -- in the ORIGINAL direction of a flow, so a reply the VM itself sent
# is never matched. One exception is rendered ABOVE it: the control uid may reach
# the guest SSH forward port range, because `cogbox ssh` (which Terminal depends
# on) dials the passt forward bound at bindAddr. Every uid, because in-VM builds
# run as `nixbld*` under the daemon and evaluate attacker-controlled flakes with
# network egress and import-from-derivation available, so ANY list of
# named uids leaves the most hostile code on the VM outside the rule by
# construction. Covering the proxy uid is not optional either: in `rules` mode
# guest 80/443 is funneled to l7proxy, which re-resolves host-side and opens the
# upstream socket under ITS uid, so a passt-only drop would let a hostile owner
# point an A record at the VM's internal IP, add an L7 allow, and obtain
# guest-triggered reachability into the enclosing VM.
#
# WHY A RANGE, rather than a list of uids: the rule must NOT be narrowed.
# `skuid { cogbox-passt, cogbox-proxy }` looks like the same rule and is not --
# it leaves the most hostile code on the VM (root-run and `nixbld*` builds) and
# passt's own pre-drop sockets outside rule 2 by construction. A first attempt at
# a same-host return-path fix narrowed the deny exactly that way and silently
# reverted the every-uid property while looking like a repair, which is why the
# range is pinned by both tests/test_floor.sh and the flake check.
#
# WHY `ct direction original`, and why the skuid range ALONE was not enough.
# A same-host connection carries the VM's own address on BOTH ends, so the RETURN
# packets of a flow the exception already permitted also have daddr = the VM's
# own address -- and their destination port is the CLIENT's ephemeral port, so
# they can never match a dport-scoped accept. They fall to the deny below it.
#
# `meta skuid` cannot be fetched for a packet
# with no owning socket, so nftables breaks out of the rule and the packet
# escapes the deny. That is true, it is why a bare `ip daddr <self> drop` must
# never be used, and it is NOT sufficient. It only covers the RST the kernel
# generates when nothing is listening. passt creates its
# port-forward listening sockets BEFORE its privilege drop, so once passt is up
# the SYN-ACK has a real owning socket whose fsuid is 0: skuid resolves, no BREAK
# occurs, and the range would swallow the reply.
#
# `ct direction original` states rule 2's actual intent -- these uids may not
# OPEN a flow to the VM's own address -- as a per-packet property that survives
# the reload argument below. Measured in a netns against a REAL listener, which
# is the only setup that can tell the shapes apart:
#
#   deny shape                | exempt port, real listener | flow that survived
#                             |                            | a floor reload
#   --------------------------+----------------------------+-------------------
#   stateless                 | dropped                    | cut
#   ct state new              | connected                  | KEEPS FLOWING
#   ct direction original     | connected                  | cut
#
# REJECTED, having been measured rather than waved off:
#
#   - `ct state established,related accept` ahead of the denies, and equally
#     `ct state new` ON the deny. Both admit the reply, and neither admits a
#     guest-originated flow (its first packet is NEW, the deny drops it, and a
#     dropped OUTPUT packet is never confirmed into conntrack, so it never
#     reaches ESTABLISHED). What they do is make the exemption a property of the
#     FLOW rather than of the packet: conntrack entries are per-netns and survive
#     the create/delete/create this unit performs, so a flow established while
#     the floor was absent stays exempt for its whole lifetime. That is not
#     theoretical -- under `ct state new` a flow opened before a reload kept
#     carrying data across it (deny counter 0), while under `ct direction original`
#     and under today's stateless drop the same flow was cut. Direction
#     is a property of the packet against the flow's origin, so the deny keeps
#     the strength of the stateless rule it replaces.
#   - matching the return direction instead (`tcp sport <range>` beside the
#     dport accept). It works today, and only because passt's listener is created
#     pre-drop and therefore carries fsuid 0 = the control uid: a passt that
#     dropped privileges first would break `cogbox ssh` again, silently, and not
#     even probe 5 could see it -- the listener that probe binds is root-owned
#     too, so it would keep answering. It also widens the accept to any root
#     socket that merely BINDS a source port inside the forward range, and it is
#     TCP- and range-shaped, so every future exempt port needs its mirror rule.
#
# THE COST, stated rather than discovered later: a `ct` expression attaches
# conntrack to the VM's network namespace, which was otherwise untracked
# (networking.firewall is off and this is the only table). Every flow the VM
# makes now takes a conntrack slot, so a guest opening flows through passt can
# push nf_conntrack toward nf_conntrack_max, whose exhaustion drops NEW packets
# for the trusted half too. It is bounded by passt's own flow table and it is
# self-inflicted denial, not an escape; no notrack carve-out is added for it,
# because one would silently break any later networking.firewall/NAT user of the
# same netns.
#
# Two gaps the range form keeps CLOSED, both of which a later narrowing to named
# uids would silently re-open:
#
#   - root-run and `nixbld*` in-VM plugin builds, which are
#     processing hostile input; no `cogbox-build` uid could ever have covered
#     them, because the daemon runs them as `nixbld*`.
#   - passt's PRE-DROP listening sockets. passt creates its port-forward
#     listeners BEFORE it drops to the passt uid, and `meta skuid` matches the
#     fsuid frozen into the socket at creation time, so those sockets are owned
#     by root and escape any `skuid cogbox-passt` rule no matter how correct the
#     drop is. The range covers root, so they are covered -- and the same
#     pre-drop fact is what gives the guest-forward SYN-ACK an owning socket at
#     all, i.e. what made the direction scoping above necessary.
#
# Loopback stays deliberately OUTSIDE rule 2 (the L7 remap funnel targets it from
# the host side); rule 3 below is what covers it instead. Nor does covering every
# uid cost the trusted half anything it needs: passt BINDS at the VM address (a
# bind is unaffected by an output drop), guest-attribute writes go to link-local
# (rule 1's business), and everything else talks over unix sockets or public
# addresses. The one dial that genuinely needs the VM's own address is `cogbox
# ssh`, which is the exception rendered above the deny.
#
# Rule 3: the passt uid may not OPEN a flow to this machine's loopback, except to
# the L7 remap funnel's own targets. Scoped to the passt uid alone -- emphatically
# NOT rule 2's every-uid range -- because loopback is where the trusted half
# actually talks to itself: l7proxy dials the mitm hop, mitmproxy dials its
# upstreams, sshd, the nix daemon. A range here would cut all of it. passt is the
# only process on the VM that turns guest bytes into host sockets, so it is the
# only uid whose loopback dials can be guest-driven, and its per-flow outbound
# sockets are created AFTER the privilege drop (unlike its port-forward
# listeners, which is rule 2's problem, not this rule's).
#
# What reaches this rule:
#
#   - Ordinary guest traffic to the VM's own non-loopback address NEVER LEAVES
#     THE GUEST. passt assigns the guest the host interface's OWN address over
#     DHCP (`dhcp.c` reply.yiaddr = c->ip4.addr; passt(1) --map-guest-addr says
#     it outright: "its own address shadows that of the host"), so the guest
#     kernel routes that address to its own loopback. This is the trap that makes
#     an in-guest probe of "the VM's address" USELESS as evidence either way: a
#     connect to <self>:22 from inside the guest reaches the GUEST's sshd, both
#     halves run the same nixpkgs OpenSSH so the banners are byte-identical, and
#     rule 2's counter correctly does not move because no packet was ever sent.
#     Probe the SSH host key, or a port only the host binds, to distinguish the
#     two endpoints.
#   - A guest that CRAFTS a frame (it is root in its own VM) to the VM's own
#     non-loopback address does reach passt, which opens a real socket to that
#     address -- and rule 2 drops it. That is the path rule 2 is for.
#   - A crafted frame to a LOOPBACK address is dropped by passt itself, on tap
#     ingress, in both families (`tap.c` "Loopback address on tap interface").
#   - passt's gateway->loopback mapping is the one remaining way an address the
#     guest can name becomes 127.0.0.1 on the host, and `--no-map-gw` removes it.
#     Verified both ways in the netns reproduction: without the flag a guest
#     frame to the gateway lands on the host as
#     127.0.0.1 -> 127.0.0.1; with it,
#     nothing arrives. `--map-guest-addr` has no default in this passt (only the
#     man page claims one), and if it ever gained one it would translate to the
#     VM's own address, i.e. into rule 2.
#
# So the property "a guest cannot address the enclosing VM's services" holds --
# but its loopback half otherwise rests entirely on those passt source lines.
# Rule 3 supplies an independent layer. The
# funnel's remap table is rendered from `.network.remap` (`renderRules`), which
# accepts an arbitrary single loopback target, so anything that can write an
# instance's config can aim passt's own connect() at 127.0.0.1:22. cogworx never
# emits `remap add`, which is why this is defence in depth and not an incident.
#
# The exception admits the funnel's OWN targets and nothing else: the shim
# rewrites guest 443 -> 127.0.0.1:<l7base> and guest 80 -> 127.0.0.1:<l7base+1>
# (`zig/src/netfilter/main.zig` doRemappedConnect, targets from `renderRules`),
# under the passt uid, post-drop. <l7base+2> is the mitmproxy SOCKS5 hop, dialed
# by l7proxy under the PROXY uid, and is deliberately NOT admitted -- a guest
# that reached it would have the terminate tier's raw upstream with no vetting.
# The exception spans l7PortTriples triples because cogbox slides the base by 3
# when the triple is taken.
#
# ONE further socket joins that allow-list and nothing else does: the VM's own
# DNS forwarder (systemd-resolved's stub at `hostResolver`:`hostResolverPort`,
# 127.0.0.53:53). It is here because guest/host resolution parity has no other
# shape that leaves rule 1 alone. passt intercepts the guest's queries
# (`--dns-forward`) and re-emits them host-side to `--dns-host`; that re-emitted
# socket is owned by the PASST uid, so a dns_host of 169.254.169.254 -- the
# metadata address, and what the DEFAULT `vpcResolver` is -- is byte-for-byte the
# guest dialling the metadata API and rule 1 drops it -- measured in a netns
# against the real rules, counter and all. Aiming dns_host at a loopback
# forwarder moves the upstream hop to a ROOT process, which rule 1 does not name,
# so the guest gains nothing: it still cannot reach any link-local address on any
# port, including 53 and 80. With a non-link-local `vpcResolver`, the loopback
# hop still keeps the upstream a trusted-half
# decision instead of a standing guest-reachable hole; see the option's own
# reasoning.
#
# The forwarder is a separate address from the funnel targets and does not slide
# with the L7 base, so it is rendered as its own pair of rules (udp + tcp) rather
# than folded into the funnel's port set -- one allow-list entry per socket, so
# neither widens when the other does.
#
# `ct direction original` for the same reason as rule 2, and probe 7 is what
# proves it: the funnel's SYN-ACK comes back from a real l7proxy socket with
# daddr 127.0.0.1 and the CLIENT's ephemeral port, so a stateless rule-3 deny
# would eat every funnel reply and take L7 down exactly the way the stateless
# rule-2 deny took `cogbox ssh` down. The test loads that shape and shows it.
#
# Where "the VM's own non-loopback addresses" comes from, and why an empty set
# fails the boot: the unit is deliberately early, which races DHCP, and a rule 2
# rendered from an EMPTY address set is a VACUOUS rule that a shape-based
# content check still passes -- the supervisor Requires= a unit that succeeded,
# so the sandbox would start with rule 2 enforcing nothing. ExecStartPost
# therefore exits non-zero on an empty set.
#
# TWO SOURCES, in that order, because the first one is EMPTY on a FIRST boot.
# `cogworx-self-addrs` (control-plane instance metadata) is authoritative
# whenever it carries anything: Start refreshes it from the address it observed.
# But a VM's first boot IS the insert, and at insert time no address has been
# allocated yet, so the control plane necessarily stamps the key empty.
# An empty first-boot attribute therefore uses the provider's interface data
# instead of failing the boot.
#
# The fallback is therefore the METADATA SERVER's own statement of the addresses
# it attached to this instance. That is a NAMED, non-guest-controllable source,
# not a guess: it is read by a root unit over the link-local channel before any
# guest exists, and the guest is structurally denied that channel for the rest of
# the VM's life (rule 1 plus passt's --no-map-gw). It is the same value the
# control plane would have written, taken one hop closer to the truth. An empty
# set from BOTH sources still fails the boot.
{ config, pkgs, ... }:
let
	cfg = config.cogworx.gce;
	sshLo = cfg.guestSSHPort;
	sshHi = cfg.guestSSHPort + cfg.guestSSHPortRange - 1;
	# Rule 3's probe targets, named once so the install and verify legs cannot
	# drift: the first funnel target (must stay reachable from the passt uid) and
	# the mitm hop of the same triple, which sits INSIDE the funnel window and is
	# deliberately outside the accept -- the sharpest available deny target.
	funnelPort = cfg.l7PortBase;
	mitmPort = cfg.l7PortBase + 2;
	# The host's own DNS forwarder, read from the SAME option the forwarder is
	# configured from (gce/cogbox-host.nix `hostResolver`), so the accept below,
	# the probe that verifies it, passt's `--dns-host` and the L4 shim's seed
	# cannot name different sockets.
	dnsFwdAddr = cfg.hostResolver;
	dnsFwdPort = cfg.hostResolverPort;

	# Rule 2's deny covers EVERY uid, expressed as a skuid RANGE. 4294967295 is
	# (uid_t)-1, the "no uid" sentinel and never a real account, so 0-4294967294
	# spans every uid that can own a socket. One rule per address, one mechanism:
	# named per-uid counters would be a second, narrower statement of the same
	# policy sitting beside this one, and the two could drift. See the header for
	# why the form is a skuid range rather than either a bare `ip daddr` drop or
	# an enumeration of names.
	denyUids = "0-4294967294";

	install = pkgs.writeShellApplication {
		name = "cogworx-floor-install";
		runtimeInputs = [ pkgs.curl pkgs.nftables pkgs.coreutils ];
		text = ''
			# Both overrides exist for tests/test_floor.sh, the same seam
			# gce/supervise.sh uses. A systemd unit starts from a clean
			# environment, so neither is set in production, and anything able to
			# set them on this unit is already root.
			MD="''${COGWORX_MD_BASE:-http://metadata.google.internal/computeMetadata/v1}"
			RUN_DIR="''${COGWORX_RUN_DIR:-/run}"
			hdr='Metadata-Flavor: Google'
			mkdir -p "$RUN_DIR"

			raw=""
			if out=$(curl -fsS -H "$hdr" --max-time 10 "$MD/instance/attributes/cogworx-self-addrs" 2>/dev/null); then
				raw="$out"
			fi

			# THE FIRST-BOOT FALLBACK (see the header). An insert stamps the
			# attribute empty because no address exists yet, so ask the
			# provider directly rather than refusing the boot. The interface
			# index listing names one entry per NIC ("0/", "1/", ...).
			if [ -z "''${raw//[[:space:]]/}" ]; then
				nics=""
				if out=$(curl -fsS -H "$hdr" --max-time 10 "$MD/instance/network-interfaces/" 2>/dev/null); then
					nics="$out"
				fi
				read -r -a nictoks <<< "$(printf '%s' "$nics" | tr ',\n\t' '   ')"
				for nic in ''${nictoks[@]+"''${nictoks[@]}"}; do
					if out=$(curl -fsS -H "$hdr" --max-time 10 "$MD/instance/network-interfaces/''${nic%/}/ip" 2>/dev/null); then
						raw="$raw $out"
					fi
				done
				if [ -n "''${raw//[[:space:]]/}" ]; then
					echo "cogworx-floor: cogworx-self-addrs was empty (first boot); rule 2 rendered from the metadata server's own interface addresses"
				fi
			fi

			# Accept space-, comma- or newline-separated entries, with or
			# without a prefix length. nft matches the ADDRESS: a CIDR from
			# the control plane must never be loaded verbatim, or a /20 would
			# turn "the VM itself" into "the whole sandbox subnet".
			read -r -a toks <<< "$(printf '%s' "$raw" | tr ',\n\t' '   ')"
			addrs=()
			for tok in ''${toks[@]+"''${toks[@]}"}; do
				a="''${tok%%/*}"
				if [ -n "$a" ]; then
					addrs+=("$a")
				fi
			done

			# Record what rule 2 was actually rendered from, so ExecStartPost
			# probes the same set the ruleset carries rather than re-reading
			# metadata that may have changed between the two.
			printf '%s\n' ''${addrs[@]+"''${addrs[@]}"} > "$RUN_DIR/cogworx-self-addrs"

			# RULE 3's funnel exception, built from build-time constants only:
			# the first TWO ports of each of the l7PortTriples triples cogbox
			# may slide onto, and never the third (the mitmproxy SOCKS5 hop --
			# l7proxy's business, under the proxy uid, and a raw un-vetted
			# upstream for anything that reached it). An nft set rather than a
			# port range, because a range cannot skip every third port.
			funnel=""
			fb=${toString cfg.l7PortBase}
			ft=0
			while [ "$ft" -lt ${toString cfg.l7PortTriples} ]; do
				funnel="''${funnel}''${funnel:+, }$fb, $((fb + 1))"
				fb=$((fb + 3))
				ft=$((ft + 1))
			done

			rules="$RUN_DIR/cogworx-floor.nft"
			{
				# The create/delete/create prelude makes the load idempotent
				# without a conditional: `delete` on a table that the previous
				# line just created always succeeds.
				printf 'table inet cogworx_floor\n'
				printf 'delete table inet cogworx_floor\n'
				printf 'table inet cogworx_floor {\n'
				printf '\tchain output {\n'
				printf '\t\ttype filter hook output priority 0; policy accept;\n'
				printf '\t\tmeta skuid "%s" ip daddr 169.254.0.0/16 counter drop comment "cogworx-floor-rule1-linklocal"\n' \
					'${cfg.passtUser}'
				# The exception, ahead of the deny and load-bearing rather than
				# decorative: the control uid sits INSIDE the deny's range, so
				# without this rule `cogbox ssh` -- and Terminal with it -- is
				# dropped. Probe 4 asserts exactly that.
				for a in ''${addrs[@]+"''${addrs[@]}"}; do
					printf '\t\tmeta skuid "%s" ip daddr %s tcp dport %s-%s counter accept comment "cogworx-floor-rule2-control-ssh"\n' \
						'${cfg.controlUser}' "$a" '${toString sshLo}' '${toString sshHi}'
				done
				# The deny: EVERY uid through a skuid RANGE, and only the
				# ORIGINAL direction of a flow. Both halves are load-bearing and
				# neither substitutes for the other (see the header). The range
				# keeps root-run/`nixbld*` plugin builds and passt's pre-drop
				# listening sockets inside the rule, and lets socket-less kernel
				# packets BREAK past it; `ct direction original` is what stops the
				# rule eating the SYN-ACK of a flow the exception above already
				# permitted, which a real listener -- unlike the RST from an empty
				# port the first fix was checked against -- generates from a real
				# socket. Narrowing either half breaks the return path.
				for a in ''${addrs[@]+"''${addrs[@]}"}; do
					printf '\t\tmeta skuid ${denyUids} ct direction original ip daddr %s counter drop comment "cogworx-floor-rule2-self"\n' "$a"
				done
				# RULE 3, the loopback leg. Rendered from build-time constants,
				# so it stands even when the address set is empty (that case
				# still fails the boot in ExecStartPost -- rule 2 would be
				# vacuous -- but rule 3 is never vacuous). The funnel accept is
				# ABOVE the deny and is the only thing keeping the L7 remap
				# funnel alive; the deny is scoped to the passt uid ALONE, never
				# rule 2's range, because loopback is where the trusted half
				# talks to itself. See the header.
				printf '\t\tmeta skuid "%s" ct direction original ip daddr 127.0.0.1 tcp dport { %s } counter accept comment "cogworx-floor-rule3-l7-funnel"\n' \
					'${cfg.passtUser}' "$funnel"
				# THE HOST DNS FORWARDER, the second and only other member of
				# rule 3's allow-list. One address, one port, both protocols,
				# and NOT folded into the funnel set above: that set is
				# 127.0.0.1-scoped and slides with the L7 base, while this is a
				# different address that never slides, so sharing one rule would
				# make each of them widen when the other did.
				#
				# Why it is needed and why it is this narrow: passt re-emits the
				# guest's intercepted DNS queries (`--dns-forward`) as an
				# ordinary socket under the passt uid, to `--dns-host`. Pointing
				# dns_host at the metadata address -- what the default
				# `vpcResolver` is -- would make that socket indistinguishable
				# from the guest dialling the metadata API, so rule 1 drops it --
				# MEASURED, not assumed. Pointing it at a
				# loopback forwarder instead moves the link-local hop to a ROOT
				# process rule 1 does not name, and leaves rule 1 completely
				# untouched: the guest still cannot reach 169.254.0.0/16 on any
				# port, including 53 and 80. What this admits is one loopback
				# socket that answers DNS and nothing else -- not port 53 to
				# loopback generally, and emphatically not the mitmproxy SOCKS5
				# hop, which sits on 127.0.0.1 and stays denied by the rule
				# below.
				printf '\t\tmeta skuid "%s" ct direction original ip daddr %s udp dport %s counter accept comment "cogworx-floor-rule3-dns-forwarder"\n' \
					'${cfg.passtUser}' '${dnsFwdAddr}' '${toString dnsFwdPort}'
				printf '\t\tmeta skuid "%s" ct direction original ip daddr %s tcp dport %s counter accept comment "cogworx-floor-rule3-dns-forwarder"\n' \
					'${cfg.passtUser}' '${dnsFwdAddr}' '${toString dnsFwdPort}'
				printf '\t\tmeta skuid "%s" ct direction original ip daddr 127.0.0.0/8 counter drop comment "cogworx-floor-rule3-loopback"\n' \
					'${cfg.passtUser}'
				# The v6 mirror. Free today (the sandbox subnet is IPv4-only and
				# passt enables v6 only with a v6 route, so the guest has none)
				# and it closes the half that would silently open if the shared
				# subnet were ever flipped to dual-stack. The funnel has no v6
				# target -- l7proxy binds 127.0.0.1 -- so there is nothing to
				# except above it.
				printf '\t\tmeta skuid "%s" ct direction original ip6 daddr ::1 counter drop comment "cogworx-floor-rule3-loopback6"\n' \
					'${cfg.passtUser}'
				printf '\t}\n'
				printf '}\n'
			} > "$rules"

			nft -f "$rules"
			echo "cogworx-floor: ruleset loaded (rule 2 denies ''${#addrs[@]} address(es) from every uid, skuid ${denyUids}, in the original direction only, with the ${cfg.controlUser} guest-SSH exception above it; rule 3 denies ${cfg.passtUser} the whole of loopback except the ${toString cfg.l7PortTriples} L7 funnel target pairs from ${toString cfg.l7PortBase} and the host DNS forwarder at ${dnsFwdAddr}:${toString dnsFwdPort})"
		'';
	};

	verify = pkgs.writeShellApplication {
		name = "cogworx-floor-verify";
		# systemd only for probe 5's listener (systemd-socket-activate); it is
		# already in every NixOS closure, so this adds nothing to the image.
		runtimeInputs = [ pkgs.util-linux pkgs.coreutils pkgs.bash pkgs.systemd ];
		text = ''
			# Test seam only, matching the install leg and gce/supervise.sh; a
			# systemd unit starts from a clean environment so this is never set
			# in production.
			RUN_DIR="''${COGWORX_RUN_DIR:-/run}"

			# THE EMPTY-SET FAIL-CLOSED. A rule 2 rendered from no addresses is
			# vacuous, and the supervisor's Requires= would still be satisfied.
			# This fires only when BOTH sources were empty: the install script
			# falls back to the metadata server's own interface addresses when
			# cogworx-self-addrs is absent or empty (a first boot), so reaching
			# here means the provider named no address for this VM either.
			self=""
			if [ -r "$RUN_DIR/cogworx-self-addrs" ]; then
				self=$(head -n1 "$RUN_DIR/cogworx-self-addrs")
			fi
			if [ -z "$self" ]; then
				echo "cogworx-floor: neither cogworx-self-addrs nor the metadata server named an address for this vm; rule 2 would be vacuous. Refusing the boot." >&2
				exit 1
			fi

			# Classify one connect attempt into the three outcomes this
			# platform actually distinguishes. A DROP (not a reject) makes the
			# connect hang until `timeout` gives up, so rc 124 is what "denied"
			# looks like; a closed-but-reachable port answers RST immediately,
			# so a fast non-zero rc is "reachable, nothing listening". That
			# difference is the entire mechanism -- it is what lets a deny probe
			# tell "enforced" from "nothing is listening", and it is what lets
			# the exception probe below assert NOT-BLOCKED without needing a
			# listener that cannot exist yet. There is exactly one classifier
			# here on purpose; a second mechanism would drift from this one.
			probe() {
				local user="$1" addr="$2" port="$3" rc=0
				setpriv --reuid "$user" --regid "$user" --clear-groups -- \
					timeout 3 bash -c "exec 3<>/dev/tcp/$addr/$port" >/dev/null 2>&1 || rc=$?
				case "$rc" in
					0) echo open ;;
					124) echo blocked ;;
					*) echo refused ;;
				esac
			}

			fails=0
			deny() {
				local what="$1" got
				got=$(probe "$2" "$3" "$4")
				if [ "$got" != blocked ]; then
					echo "cogworx-floor: PROBE FAILED: $what ($2 -> $3:$4) was $got, expected blocked" >&2
					fails=$((fails + 1))
				fi
			}
			# The exception's polarity: NOT-BLOCKED, never CONNECTED. Only a
			# DROP (rc 124 -> "blocked") proves the exception broken; "open" and
			# "refused" both prove it intact. See probe 4 below for why
			# "refused" is the healthy answer at floor time, and why demanding
			# "open" would be unsatisfiable by construction.
			not_blocked() {
				local what="$1" got
				got=$(probe "$2" "$3" "$4")
				if [ "$got" = blocked ]; then
					echo "cogworx-floor: PROBE FAILED: $what ($2 -> $3:$4) was dropped, expected connected or refused" >&2
					fails=$((fails + 1))
				fi
			}

			# 1. rule 1: the passt uid must not reach the metadata API.
			#    The address is the METADATA constant, spelled out, and must NOT
			#    be refactored into `cfg.vpcResolver` for looking like the same
			#    value: that option may point elsewhere, and the probe would then stop
			#    testing rule 1's actual invariant -- the guest's total exclusion
			#    from the link-local metadata surface, which holds whatever the
			#    DNS upstream is. gce-image-unit-ordering pins the literal.
			deny "rule 1, metadata API" '${cfg.passtUser}' 169.254.169.254 80
			# 2. rule 2, passt leg: the passt uid must not reach the VM itself.
			#    Two of the range's members are probed by name, not because the
			#    rule enumerates them but because they are the two the design
			#    names as attackers of this rule.
			deny "rule 2, passt leg" '${cfg.passtUser}' "$self" '${toString sshLo}'
			# 3. rule 2, proxy leg: the RELAY attack. An L7-allowed name
			#    resolving to the VM's own address must not become
			#    guest-triggered reachability into the enclosing VM.
			deny "rule 2, proxy leg" '${cfg.proxyUser}' "$self" '${toString cfg.l7PortBase}'
			# 4. the exception, asserted as NOT-BLOCKED rather than as CONNECTED.
			#    Rule 2 covers the control uid like every other, so this probe is
			#    what proves the accept above the deny is present and correctly
			#    ordered; without it `cogbox ssh` and Terminal break, and the
			#    obvious remedy is to widen rule 2 rather than restore the
			#    exception -- a broken exception must fail the boot, not create
			#    widening pressure.
			#
			#    But it must assert the WEAK claim, because the strong one is
			#    unsatisfiable here by construction: this unit runs BEFORE
			#    cogworx-supervisor.service (which Requires= it), and passt --
			#    the process that binds the guest SSH forward -- is started by
			#    that supervisor. So at probe time nothing can possibly be
			#    listening on the port, and a correct VM answers RST, not a
			#    completed handshake. Demanding "open" would fail every single
			#    boot of a correctly built image; "open" happens only when the
			#    unit is re-run while a sandbox is already up.
			#
			#    The three deny probes above keep the OPPOSITE polarity exactly:
			#    anything other than "blocked" fails them, so a floorless VM --
			#    where every probe answers "refused" -- still refuses to start a
			#    sandbox. Only this one probe treats "refused" as healthy.
			not_blocked "rule 2 control-uid exception" '${cfg.controlUser}' "$self" '${toString sshLo}'

			# 5. THE EXEMPT-PORT RETURN PATH, and the reason probe 4 alone was
			#    not enough. Probe 4 cannot tell a working exception from a
			#    broken one once something is actually LISTENING: with an empty
			#    port the answer is a socket-less kernel RST, which BREAKs out of
			#    any skuid rule and surfaces as "refused" -- healthy-looking
			#    under the correct deny and under the broken one alike. A real
			#    listener's SYN-ACK comes from a real socket, matches an unscoped
			#    deny, and is eaten.
			#
			#    So this probe brings its own listener rather than waiting for
			#    passt: a root-owned socket bound to the VM's own address on a
			#    port inside the exempt range, which is exactly how passt binds
			#    its forward (pre-drop, fsuid 0). It is the one probe allowed to
			#    demand "open", because it is the one probe that creates the
			#    conditions for it. The listener is bounded by `timeout` and torn
			#    down here, before the supervisor -- and therefore passt -- runs.
			#
			#    systemd-socket-activate is the listener because systemd is
			#    already in this image's closure: a floor unit should not add a
			#    network utility to a hardened VM merely to test itself. A
			#    "refused" means the listener has not bound yet, so the probe
			#    retries; "blocked" is decided immediately, since only the deny
			#    can produce it.
			retp='${toString sshHi}'
			timeout 10 systemd-socket-activate -l "$self:$retp" --accept ${pkgs.coreutils}/bin/true >/dev/null 2>&1 &
			lpid=$!
			got=refused
			for _ in 1 2 3 4 5 6 7 8 9 10; do
				got=$(probe '${cfg.controlUser}' "$self" "$retp")
				[ "$got" = refused ] || break
				sleep 0.2
			done
			kill "$lpid" 2>/dev/null || true
			wait "$lpid" 2>/dev/null || true
			if [ "$got" = open ]; then
				echo "cogworx-floor: exempt-port return path verified (${cfg.controlUser} completed a connection to a real listener on $self:$retp)"
			else
				echo "cogworx-floor: PROBE FAILED: rule 2 exempt-port return path (${cfg.controlUser} -> $self:$retp, with a listener bound) was $got, expected open" >&2
				fails=$((fails + 1))
			fi

			# 6 and 7. RULE 3, both polarities, and BOTH against a real listener
			#    for the reason probe 5 exists: an empty port answers a
			#    socket-less kernel RST, which BREAKs out of any skuid rule and
			#    reads as a healthy "refused" under the correct rule and a broken
			#    one alike.
			#
			#    The listener is bound and confirmed reachable from the CONTROL
			#    uid first. That serves two purposes at once: it is how we know
			#    the socket is up before the meaningful probe runs, and it is the
			#    negative control for rule 3's uid scoping -- the same address,
			#    the same port, a uid rule 3 does not name, and it connects.
			#
			#    Both listeners are torn down here, before the supervisor (and
			#    therefore l7proxy) runs, so neither can push cogbox's launch-time
			#    triple probe onto a slid base.
			lo_probe() {
				local port="$1" pid got=refused
				timeout 10 systemd-socket-activate -l "127.0.0.1:$port" \
					--accept ${pkgs.coreutils}/bin/true >/dev/null 2>&1 &
				pid=$!
				for _ in 1 2 3 4 5 6 7 8 9 10; do
					[ "$(probe '${cfg.controlUser}' 127.0.0.1 "$port")" = refused ] || break
					sleep 0.2
				done
				got=$(probe '${cfg.passtUser}' 127.0.0.1 "$port")
				kill "$pid" 2>/dev/null || true
				wait "$pid" 2>/dev/null || true
				echo "$got"
			}

			# 6. The deny. The target is the mitmproxy SOCKS5 hop of the first L7
			#    triple: it sits INSIDE the window the funnel exception spans, so
			#    a "blocked" here proves the exception is a set of named funnel
			#    ports and not a port RANGE that swallowed the third port with
			#    them. A guest reaching that hop would have the terminate tier's
			#    raw upstream with no vetting at all.
			got=$(lo_probe '${toString mitmPort}')
			if [ "$got" = blocked ]; then
				echo "cogworx-floor: rule 3 verified (${cfg.passtUser} cannot open a flow to a live listener on 127.0.0.1:${toString mitmPort}, inside the funnel window and outside the funnel ports)"
			else
				echo "cogworx-floor: PROBE FAILED: rule 3, loopback leg (${cfg.passtUser} -> 127.0.0.1:${toString mitmPort}, with a listener bound) was $got, expected blocked" >&2
				fails=$((fails + 1))
			fi

			# 7. The exception, and the ONLY probe on this unit that can catch a
			#    rule 3 which closed the hole by killing the L7 remap funnel with
			#    it. It demands "open" and is allowed to for probe 5's reason: it
			#    creates the conditions for it. A stateless rule-3 deny passes
			#    probe 6 and fails here -- the funnel's SYN-ACK carries daddr
			#    127.0.0.1 and the client's ephemeral port, so no dport accept can
			#    match it -- which is the whole argument for `ct direction
			#    original` on this rule as well as on rule 2.
			got=$(lo_probe '${toString funnelPort}')
			if [ "$got" = open ]; then
				echo "cogworx-floor: L7 funnel exception verified (${cfg.passtUser} completed a connection to a real listener on the funnel target 127.0.0.1:${toString funnelPort})"
			else
				echo "cogworx-floor: PROBE FAILED: rule 3 L7 funnel exception (${cfg.passtUser} -> 127.0.0.1:${toString funnelPort}, with a listener bound) was $got, expected open" >&2
				fails=$((fails + 1))
			fi

			# 8. RULE 3's other exception: the host's own DNS forwarder. This is
			#    the ONE probe that needs no listener of its own, because the
			#    listener is the forwarder itself -- systemd-resolved's stub,
			#    started well before this unit -- and that is exactly why it may
			#    demand "open" rather than not-blocked. Both halves of the
			#    demand are load-bearing:
			#
			#      - "blocked" means the accept is missing or ordered below the
			#        deny, so passt's re-emitted DNS query would be dropped and
			#        EVERY guest on this VM would have no DNS, silently.
			#      - "refused" means the forwarder is not listening on the socket
			#        this image points passt and the shim at, which is the same
			#        outage arriving from the other side. Failing the boot on it
			#        is what makes hostResolver/hostResolverPort safe to state in
			#        one place: a value that names a socket nothing binds cannot
			#        reach a running sandbox.
			got=$(probe '${cfg.passtUser}' '${dnsFwdAddr}' '${toString dnsFwdPort}')
			if [ "$got" = open ]; then
				echo "cogworx-floor: host DNS forwarder exception verified (${cfg.passtUser} completed a connection to ${dnsFwdAddr}:${toString dnsFwdPort}, the only loopback socket outside 127.0.0.1's funnel targets it may open)"
			else
				echo "cogworx-floor: PROBE FAILED: rule 3 host DNS forwarder exception (${cfg.passtUser} -> ${dnsFwdAddr}:${toString dnsFwdPort}) was $got, expected open; guest DNS would be dropped and every sandbox on this VM would resolve nothing" >&2
				fails=$((fails + 1))
			fi

			if [ "$fails" -gt 0 ]; then
				echo "cogworx-floor: $fails floor probe(s) failed; the sandbox must not start" >&2
				exit 1
			fi
			echo "cogworx-floor: all eight floor probes passed"
		'';
	};
in
{
	config = {
		# networking.firewall.enable is mkDefault false in the GCE profile, so
		# nothing installs a floor unless this unit does.
		# nft_ct/nf_conntrack because rule 2's deny is direction-scoped: the `ct`
		# expression is what attaches conntrack to this netns. The kernel would
		# autoload them for a root nft load anyway; naming them here makes the new
		# dependency visible and fails loudly at modules-load rather than as an
		# unexplained `nft -f` error.
		boot.kernelModules = [ "nf_tables" "nf_conntrack" "nft_ct" ];

		systemd.services.cogworx-floor = {
			description = "Install and verify the cogworx enforcement floor (nftables)";
			wantedBy = [ "multi-user.target" ];
			# systemd-resolved because probe 8 connects to its stub listener and
			# demands a completed connection. resolved is a sysinit service and
			# would almost always be up first anyway; ordering it explicitly
			# turns "almost always" into a guarantee, and After= on a Type=notify
			# unit means the stub is BOUND, not merely started.
			after = [ "network-online.target" "systemd-resolved.service" ];
			wants = [ "network-online.target" "systemd-resolved.service" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${install}/bin/cogworx-floor-install";
				ExecStartPost = "${verify}/bin/cogworx-floor-verify";
			};
		};
	};
}
