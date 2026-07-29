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
{ config, lib, pkgs, ... }:
let
	cfg = config.cogworx.gce;
	# systemd-escaped mount unit name for cfg.stateDir. Hard-coded rather than
	# computed because it also appears verbatim in unit ordering below and in
	# the gce-image-state-disk-ordering check.
	mountUnit = "var-lib-cogbox\\x2dstate.mount";
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
