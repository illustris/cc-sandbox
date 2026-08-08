# /var/lib/cogbox-state: the filesystem every other path in both repos already
# assumed existed, and nothing created.
#
# Load-bearing consumers, so the ordering below is not housekeeping:
#   - sshd's HostKey. sshd reading its host key off an UNMOUNTED path
#     writes a fresh key onto the boot disk instead, which survives until the
#     next Stop or boot-disk swap and then vanishes, silently resetting trust.
#   - XDG_CONFIG_HOME / COGBOX_DATA: cogbox config.json, the per-instance L7
#     CA, the secret store, the guest host key.
#   - the control plane's per-VM instance dir.
#
# The mkfs is CONDITIONAL, and that condition is the whole safety argument: an
# unconditional mkfs on a resumed instance destroys the L7 CA private key, the
# secret store and the VM host key in one step, on every Start.
{ config, lib, pkgs, utils, ... }:
let
	cfg = config.cogworx.gce;
	# systemd-escaped mount unit name for cfg.stateDir. Hard-coded rather than
	# computed because it also appears verbatim in unit ordering below and in
	# the gce-image-state-disk-ordering check.
	mountUnit = "var-lib-cogbox\\x2dstate.mount";
	# ...and the fsck instance systemd-fstab-generator SYNTHESISES for the same
	# mount, which is DERIVED and never spelled: the pass-2 fstab line below makes
	# the generator emit `Requires=systemd-fsck@<escaped device>.service` on the
	# mount unit, and stateDevice is an option, so a hard-coded name would silently
	# orphan the bound the moment an operator points it elsewhere.
	# gce-image-host-boot-bounded re-derives this from the GENERATOR'S output and
	# fails if the rendered drop-in does not match, which is the only way to catch
	# an escaping mistake.
	fsckUnit = "systemd-fsck@${utils.escapeSystemdPath cfg.stateDevice}.service";
in
{
	config = {
		systemd.services.cogworx-state-disk = {
			description = "Format the cogworx state disk on first boot only";
			# Deliberately NOT wantedBy anything: the mount pulls it in via
			# x-systemd.requires below, so it runs exactly when the filesystem
			# is about to be needed and not at all on a VM with no state disk.
			after = [ "local-fs-pre.target" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				# EXPLICIT, because the default here is NO TIMEOUT AT ALL --
				# systemd.service(5) on TimeoutStartSec=: "Defaults to
				# DefaultTimeoutStartSec= set in the manager, except when
				# Type=oneshot is used, in which case the timeout is DISABLED by
				# default." That is the same sentence gce/guest-disk.nix quotes to
				# justify its own bound, and this unit needed it more: the mount
				# below hard-Requires= this service AND carries
				# x-systemd.before=sshd.service and
				# x-systemd.before=cogworx-supervisor.service, so an unbounded hang
				# here takes BOTH the host's sshd and the VM launcher with it -- and
				# with the supervisor gone there is no `ssh <vm> cogbox <verb>`
				# control channel left, i.e. no recovery path at all. The shape is a
				# state PD that answers its 30s device probe and then stalls on
				# reads: blkid parks in D-state, the oneshot's start job never
				# completes, and the VM sits in Booting forever with an EMPTY
				# `systemctl --failed` because the units are `activating`, not
				# failed. `nofail` does not help -- it unhooks the mount from
				# local-fs.target and leaves the explicit x-systemd.before= edges
				# exactly where they are. nofail bounds FAILURE; only a timeout
				# bounds a HANG.
				#
				# 600s matches gce/guest-disk.nix rather than being tuned: the legs
				# here are one blkid and at most one mkfs.ext4 (lazy_itable_init, so
				# seconds regardless of disk size), and anything past ten minutes is
				# a fault and not slow progress. Being killed at the deadline is
				# safe for the same reason a host crash mid-mkfs is: the blkid guard
				# re-runs on the next boot and either finds a signature and refuses
				# or finds none and finishes the interrupted format. The stop half
				# needs nothing set -- this is an ordinary NixOS-rendered service, so
				# the manager's finite DefaultTimeoutStopSec applies and SIGKILL
				# escalation still gets the unit to `failed` rather than parking it
				# in `deactivating`. (The fsck drop-in below is the opposite case and
				# does set both, because its upstream template says
				# TimeoutSec=infinity, which overrides start AND stop.)
				TimeoutStartSec = 600;
				ExecStart = "${pkgs.writeShellApplication {
					name = "cogworx-state-disk";
					runtimeInputs = [ pkgs.util-linux pkgs.e2fsprogs pkgs.coreutils ];
					text = ''
						dev=${cfg.stateDevice}
						if [ ! -b "$dev" ]; then
							# A resolver VM is the backend image with no
							# state disk attached. Succeed so the boot continues;
							# the mount is `nofail` and everything that needs the
							# disk fails closed on its own terms.
							echo "cogworx-state-disk: $dev is not attached; nothing to format"
							exit 0
						fi
						if blkid -p -o value -s TYPE "$dev" >/dev/null 2>&1; then
							echo "cogworx-state-disk: $dev already carries a filesystem; leaving it alone"
							exit 0
						fi
						echo "cogworx-state-disk: $dev is unformatted; creating ext4"
						mkfs.ext4 -q -L cogworx-state "$dev"
					'';
				}}/bin/cogworx-state-disk";
			};
		};

		# The OTHER job on this mount's start path, and the one an audit of "every
		# unit this file writes" cannot see, because this file does not write it:
		# the fstab entry below is fs_passno 2, so systemd-fstab-generator
		# synthesises `Requires=` + `After=` a systemd-fsck@<device>.service
		# instance on the mount unit. Upstream systemd-fsck@.service ships
		# `TimeoutSec=infinity` and there is no drop-in for the instance, so e2fsck
		# on a state PD that stalls mid-read sits in D-state forever, the mount's
		# start job never completes, and the mount's own
		# x-systemd.before=sshd.service / =cogworx-supervisor.service edges hold
		# both indefinitely. Same wedge as the unbounded oneshot above, arriving
		# through a unit name that appears nowhere in either repository.
		#
		# BOTH halves are set, and the stop half is the load-bearing one:
		# TimeoutSec=infinity sets the START *and the STOP* timeout. Bounding only
		# the start fires SIGTERM at a process wedged in D-state on the very device
		# that stalled and then waits forever for it to die -- the unit parks in
		# `deactivating`, the job still never completes, and the host is wedged
		# exactly as before, one state further along. With both set systemd
		# escalates SIGTERM -> SIGKILL -> "processes still around after final
		# SIGKILL, ignoring", the unit reaches `failed`, and the mount fails rather
		# than hanging -- at which point `nofail` finally does its job and the boot
		# continues without the state disk, which is the degradation state-disk.nix
		# is already written for (the supervisor asserts the mount for itself).
		#
		# 600s to match the format unit above; a full e2fsck of a 32 GiB ext4 that
		# is making progress finishes far inside that.
		#
		# overrideStrategy = "asDropin" is REQUIRED and not stylistic. The default,
		# asDropinIfExists, looks for a systemd-fsck@<instance>.service to extend,
		# finds nothing (the instance is generated at runtime, not rendered), and
		# installs this as a WHOLE UNIT shadowing the template -- a unit with no
		# ExecStart, which succeeds instantly, so the state disk would silently
		# never be checked again. That is a failure in the direction of data loss
		# rather than of a wedge, and gce-image-host-boot-bounded asserts against
		# it. This mirrors the guest-side poolJobTimeout drop-ins in flake.nix,
		# spelled out here rather than shared because that binding lives inside the
		# guest module's let and this is the host.
		#
		# Assembled with concatStringsSep rather than as an indented string
		# literal, and that is not style: an indented literal here renders the
		# leading TABS into the drop-in body (measured), and a drop-in whose
		# directives are indented is one systemd may or may not accept depending on
		# its parser's whitespace handling -- exactly the kind of thing that would
		# be discovered on a wedged host. flake.nix's poolJobTimeout is built the
		# same way for the same reason.
		systemd.units.${fsckUnit} = {
			overrideStrategy = "asDropin";
			text = lib.concatStringsSep "\n" [
				"[Service]"
				"TimeoutStartSec=600"
				"TimeoutStopSec=60"
				""
			];
		};

		fileSystems.${cfg.stateDir} = {
			device = cfg.stateDevice;
			fsType = "ext4";
			# Not needed in the initrd: nothing in stage 1 reads it, and
			# marking it so would put a lazily hydrated PD on the boot
			# critical path.
			neededForBoot = false;
			options = [
				# A resolver VM boots this same image with no state disk. Its
				# mount must not wedge the boot; everything that genuinely
				# needs the disk (the supervisor) checks for itself.
				"nofail"
				"x-systemd.device-timeout=30s"
				"x-systemd.requires=cogworx-state-disk.service"
				"x-systemd.after=cogworx-state-disk.service"
				# sshd-keygen is what actually writes the host key, so ordering
				# only sshd would still lose the race that regenerates it on
				# the boot disk.
				"x-systemd.before=sshd-keygen.service"
				"x-systemd.before=sshd.service"
				"x-systemd.before=cogworx-supervisor.service"
				"x-systemd.before=cogworx-attr-scrub.service"
			];
		};

		# The supervisor is ordered after the mount unit by name. It is
		# deliberately NOT `Requires=` it: leg (a2) must publish the VM host
		# key on EVERY boot class including a resolver boot, and a resolver has
		# no state disk, so a hard requirement would make the mount's failure
		# the thing that kills the resolver flow. The supervisor asserts the
		# mount for itself on the boots that need it (supervise.sh), which is
		# strictly more precise than a unit-level requirement.
		systemd.services.cogworx-supervisor.after = [ mountUnit ];
		systemd.services.cogworx-attr-scrub.after = [ mountUnit ];

		# Everything under the state dir is created by the supervisor (root) or
		# by sshd-keygen; seed the mount point itself so a stat before the
		# first mount does not surprise anything.
		systemd.tmpfiles.rules = [
			"d ${cfg.stateDir} 0755 root root -"
		];
	};
}
