# cogworx-resolver-deadline.service -- the in-VM belt for the resolver's hard
# self-destruct deadline.
#
# A resolver VM evaluates ATTACKER-CONTROLLED flakes, so "no credential, and it
# goes away" is the whole containment argument. The provider-side half of the
# deadline lives in the insert body's scheduling.maxRunDuration, whose
# acceptance on the target project and machine series is unproven:
#
# PHASE-0: confirm `scheduling.maxRunDuration` + `instanceTerminationAction`
# are accepted on the target project/series. Until that probe
# lands, this unit is the ONLY thing guaranteeing the deadline, which is why it
# exists rather than being deferred to the API field.
#
# Armed strictly from the `cogworx-resolver` metadata flag, so a sandbox VM
# booting the same image is never touched.
{ config, lib, pkgs, ... }:
let
	defaultDeadline = 600;
	arm = pkgs.writeShellApplication {
		name = "cogworx-resolver-deadline";
		runtimeInputs = [ pkgs.curl pkgs.coreutils pkgs.systemd ];
		text = ''
			MD=http://metadata.google.internal/computeMetadata/v1
			hdr='Metadata-Flavor: Google'

			# Reachability first, so "attribute absent" and "endpoint down" are
			# never confused: the second is a retry, the first is success. Same
			# leg, and same wording, as cogworx-attr-scrub -- but the failure
			# DIRECTIONS are not the same, which is why this one is the more
			# important of the two. There, confusing them costs a retry. Here,
			# "absent" means `exit 0`, and under RemainAfterExit=true that
			# LATCHES success for the whole boot: Restart=on-failure never
			# fires, nothing re-queues the unit, and the deadline NEVER ARMS on
			# a VM whose entire containment argument is that it goes away
			# while it evaluates attacker-controlled flakes. A fail-open
			# leak, not a delayed one.
			if ! curl -fsS -o /dev/null -H "$hdr" --max-time 10 "$MD/instance/id"; then
				echo "cogworx-resolver-deadline: metadata endpoint unreachable; will retry" >&2
				exit 1
			fi

			# Key PRESENCE, never value: the control plane clears a flag by
			# removing the item. The probe above makes an unreachable endpoint a
			# retry, but it cannot cover this read itself, and `-f` would not
			# either: MEASURED, curl -f exits 22 on a 404 AND on a 500 alike, so
			# a metadata server erroring in the window since the probe would read
			# as "flag absent" and latch. Only 404 means absent, so the STATUS is
			# read rather than inferred from an exit code; 000 (transport) and
			# every 5xx fall through to the retry.
			code=$(curl -sS -o /dev/null -w '%{http_code}' -H "$hdr" --max-time 10 \
				"$MD/instance/attributes/cogworx-resolver" 2>/dev/null || true)
			case "$code" in
				200) ;;
				404)
					echo "cogworx-resolver-deadline: not a resolver boot; nothing to arm"
					exit 0
					;;
				*)
					echo "cogworx-resolver-deadline: could not read the cogworx-resolver flag (HTTP '$code'); will retry rather than latch an unarmed deadline" >&2
					exit 1
					;;
			esac

			dl=""
			if out=$(curl -fsS -H "$hdr" --max-time 10 "$MD/instance/attributes/cogworx-resolver-deadline" 2>/dev/null); then
				dl="$out"
			fi
			case "$dl" in
				""|*[!0-9]*) dl=${toString defaultDeadline} ;;
			esac
			# Clamp rather than trust: the deadline arrives over the same
			# metadata blob a mis-set operator value lands in, and an
			# unbounded one would defeat the containment argument entirely.
			if [ "$dl" -lt 60 ]; then dl=60; fi
			if [ "$dl" -gt 86400 ]; then dl=86400; fi

			systemd-run --unit=cogworx-resolver-poweroff --on-active="''${dl}s" \
				--description="cogworx resolver self-destruct" \
				systemctl poweroff --force
			echo "cogworx-resolver-deadline: armed; this VM powers off in ''${dl}s"
		'';
	};
in
{
	config = {
		systemd.services.cogworx-resolver-deadline = {
			description = "Arm the resolver VM self-destruct deadline";
			wantedBy = [ "multi-user.target" ];
			after = [ "network-online.target" ];
			wants = [ "network-online.target" ];
			unitConfig = {
				# A resolver whose deadline never armed is a leaked VM that
				# evaluates hostile flakes, so retry without a start limit.
				StartLimitIntervalSec = 0;
			};
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				Restart = "on-failure";
				RestartSec = 5;
				ExecStart = "${arm}/bin/cogworx-resolver-deadline";
			};
		};
	};
}
