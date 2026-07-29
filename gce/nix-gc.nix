# cogworx-nix-gc.service + .timer -- bound boot-disk growth:
# "`nix store gc` is scheduled after realise to bound boot-disk growth").
#
# "NixGCReconciler is unsupported" is a statement about the CONTROL PLANE: there
# is no node-shared CoW store to collect here, and disk lifecycle rides the
# per-instance VM/disk lifecycle. It says nothing about the VM's own boot disk,
# which fills under repeated in-VM plugin builds with no reclaim at all -- and
# on this backend the boot disk IS the store.
#
# The GC is threshold-gated rather than unconditional so a busy instance is not
# repeatedly stripped of the closures it is about to rebuild. Everything the
# booted system references -- including the flake input source trees registered
# through system.extraDependencies, which are what keep the launcher's re-exec
# evaluable offline -- is a live GC root, so this cannot eat the offline-boot
# guarantee gce-image-offline-closure asserts.
{ config, lib, pkgs, ... }:
let
	minFreeGB = 12;
	gc = pkgs.writeShellApplication {
		name = "cogworx-nix-gc";
		runtimeInputs = [ pkgs.coreutils pkgs.gawk pkgs.nix ];
		text = ''
			free_kb=$(df -Pk /nix/store | awk 'NR==2 {print $4}')
			want_kb=$(( ${toString minFreeGB} * 1024 * 1024 ))
			if [ "$free_kb" -ge "$want_kb" ]; then
				echo "cogworx-nix-gc: $(( free_kb / 1024 / 1024 )) GiB free on /nix/store; nothing to do"
				exit 0
			fi
			echo "cogworx-nix-gc: only $(( free_kb / 1024 / 1024 )) GiB free on /nix/store; collecting"
			# Classic nix-collect-garbage, not `nix store gc`: it needs no
			# experimental feature and it also drops the stale system
			# generations a long-lived sandbox VM accumulates.
			nix-collect-garbage --delete-older-than 3d
		'';
	};
in
{
	config = {
		systemd.services.cogworx-nix-gc = {
			description = "Collect the in-VM nix store when the boot disk runs low";
			serviceConfig = {
				Type = "oneshot";
				ExecStart = "${gc}/bin/cogworx-nix-gc";
				Nice = 10;
				IOSchedulingClass = "idle";
			};
		};

		systemd.timers.cogworx-nix-gc = {
			description = "Periodic in-VM nix store collection";
			wantedBy = [ "timers.target" ];
			timerConfig = {
				OnBootSec = "30min";
				OnUnitActiveSec = "6h";
				RandomizedDelaySec = "10min";
				Persistent = true;
				Unit = "cogworx-nix-gc.service";
			};
		};
	};
}
