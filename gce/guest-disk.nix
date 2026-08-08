# The per-instance GUEST data pool: carved here on first boot, grown here on
# every boot, and NEVER mounted by this host.
#
# That asymmetry with state-disk.nix is the whole reason this is a separate file
# rather than three more lines there. The state disk is the TRUSTED half's own
# storage -- this host reads the sshd host key, the per-instance L7 CA and the
# secret store off it, so it mounts it. The guest pool holds the UNTRUSTED half's
# data (the user's work tree, their tool and editor caches, their guest journal)
# and this host has no business reading any of it, so the block devices are handed
# straight through to QEMU as virtio-blk volumes and mounted only inside the guest.
#
# WHAT THIS HOST DOES DO to that disk is put an LVM volume group on it, activate
# it, keep it grown to the disk, and lay a filesystem on each logical volume. Note
# what that is and is not: the host OPENS the block devices and writes filesystem
# METADATA on first use, and it never mounts a guest filesystem or reads a byte of
# the user's files. "The host does not mount it" is a statement about the host not
# reading the user's data, and it still holds exactly.
#
# WHY LVM RATHER THAN TWO PARTITIONS. The guest needs two block devices, not one:
# the writable /nix/store overlay must be its own volume, because microvm.nix marks
# a volume neededForBoot only when its mount point IS microvm.writableStoreOverlay,
# and folding it into the pool would drag the user's data pool onto the initrd path.
# Two FIXED partitions would deliver that and then make decision 5 -- grow the
# provider disk, restart, the guest grows into it -- half true: growing a disk only
# ever yields free space AFTER the last partition, so whichever partition sits
# first can never be extended and one concern permanently blocks the other's
# growth. A volume group shares its free extents, so EITHER logical volume can take
# new space. That is the entire argument, and it is why the layout is
# host-side LVM and not host-side partitioning.
#
# The GUEST is never told about any of it. It sees two ordinary virtio-blk devices
# and mounts them BY LABEL: nothing in the guest configuration names this volume
# group, either logical volume or any device-mapper path, so there is no
# volume-group activation anywhere on the guest's boot path and no guest-side
# failure mode to get wrong.
#
# THE WRITES ARE CONDITIONAL, AND THAT CONDITION IS THE WHOLE SAFETY ARGUMENT --
# more so here than on the state disk. The state disk's worst case is a lost host
# key and a re-mintable CA; this disk holds the user's ONLY copy of their work
# tree. An unconditional mkfs on a resumed instance destroys it in one step, on
# every Start, unrecoverably. The five cases, in the order the script tests them:
#
#   the device is ABSENT      log, exit 0, and it is the ONE refusal that stays
#                             exit 0. A resolver VM boots this same image with no
#                             such device attached and must still reach
#                             multi-user.target; this unit cannot tell that boot
#                             class from a sandbox whose disk failed to attach,
#                             so it does not try. The sandbox case is caught one
#                             layer up instead, by supervise.sh leg (e2), which
#                             DOES know it is about to start a guest and names
#                             the missing volume on serial before it tries.
#
#   the device is UNREADABLE  log to stderr, exit 1. See the read-proof note
#                             below: this is the case neither signature probe can
#                             tell apart from a blank disk, and it is the disk
#                             most likely to hold data.
#
#   the device is ALREADY     log, and create NOTHING. `blkid -p` typing the disk
#   LVM (a PV signature)      LVM2_member is the already-initialised signal, and it
#                             is the ordinary steady state: every boot after the
#                             first lands here. The volume group is activated and
#                             grown from here on, but no pvcreate, no vgcreate, and
#                             no mkfs on the pool.
#
#   the device carries a      log to stderr, exit 1, touch NOTHING. Not ours. The
#   NON-LVM filesystem, or    likeliest cause is the wrong disk attached, and the
#   we CANNOT TELL            second likeliest is a probe that failed in a way
#                             that looks like an answer. Blankness has to be
#                             PROVED, not merely unrefuted, and one probe cannot
#                             prove it.
#
#                             The REFUSAL is unchanged and absolute; only its
#                             exit status changed, from 0 to 1, and that is a
#                             visibility fix rather than a behaviour one. With a
#                             launch-time fallback this boot still produced a
#                             usable guest, so exit 0 was honest. With one baked
#                             profile it produces no guest at all -- and exit 0
#                             left the unit `active`, nothing in `systemctl
#                             --failed`, and a supervisor flapping under
#                             Restart=always with no unit anywhere saying why.
#                             That shape is the failure mode this design is
#                             written against. Same for the foreign-volume-group
#                             case below.
#                             `blkid -p` exit 2 is documented as "nothing found",
#                             but it is ALSO what blkid returns when it could not
#                             look: an open() failure warns and returns
#                             BLKID_EXIT_NOTFOUND, and a low-level probe error ends
#                             at the same `if (!nvals) return BLKID_EXIT_NOTFOUND`
#                             (util-linux misc-utils/blkid.c, lowprobe_device).
#                             MEASURED: a device that cannot be read gives exit 2
#                             with empty stdout, character-for-character what a
#                             genuinely blank disk gives.
#
#                             Nor can a second SIGNATURE probe fix that on its own:
#                             MEASURED against a device-mapper `error` target,
#                             `wipefs --no-act` also reports exit 0 and no
#                             signatures, because libblkid treats a failed buffer
#                             read as "no match" rather than as an error. Two blind
#                             probes agreeing is not evidence.
#
#                             So blankness is established POSITIVELY, by a read
#                             that had to succeed, and only then refuted by the
#                             signature probes. A write needs all three: a
#                             successful `dd` of the first MiB, blkid exit 2 with
#                             no TYPE, and wipefs exit 0 with no signature listed.
#                             The dd is what closes the unreadable-disk hole;
#                             wipefs earns its place by enumerating every magic
#                             string it knows including partition tables, and by
#                             failing loudly (exit 1, "probing initialization
#                             failed") on a device it could not OPEN, where blkid
#                             returns a silent exit 2. Everything ambiguous --
#                             blkid exit 8 (its two-signature result, the shape a
#                             half-overwritten disk has), any wipefs failure, any
#                             signature wipefs lists -- lands HERE, i.e. is treated
#                             as already-initialised and left alone.
#
#                             state-disk.nix tests blkid's exit status alone and so
#                             formats on ANY nonzero: that is fail-OPEN, and
#                             acceptable only because of what that disk holds. Do
#                             not "simplify" this back to match it.
#
#   the device is BLANK       pvcreate + vgcreate + two lvcreate, and only with all
#                             three probes agreeing. Nothing else in either
#                             repository ever writes to this device from the host
#                             side.
#
# The same three-probe test is applied a SECOND time, to the pool logical volume,
# before its mkfs -- see poolBlank in the script. A fresh lvcreate yields a blank
# volume so the first boot formats it; every later boot finds ext4 there and
# refuses. That second application is what makes an interrupted first mkfs
# self-heal without ever putting a populated pool at risk.
#
# The STORE logical volume is the one deliberate exception and it is not an
# oversight: its filesystem is re-created on EVERY host boot. It is the writable
# /nix/store overlay upper, which held no user data as a tmpfs and holds none now;
# recreating it keeps that semantics exactly, self-heals an interrupted mkfs on a
# volume the guest cannot boot without, and is the only honest way to grow it --
# `x-systemd.growfs` is unavailable to a neededForBoot mount, because
# systemd-growfs@.service is a stage-2 upstream unit and this nixpkgs has no
# stage-1 resize at all.
#
# It is therefore done FIRST, before the pool is probed at all, and the order is
# load-bearing rather than tidy. The pool probe can REFUSE (an unreadable volume
# exits 1), and once the logical volumes exist a refusal no longer stops the
# guest from STARTING: both device nodes are present, so QEMU opens both drives
# and the guest boots. With the store's mkfs behind the pool probe, that boot
# handed the guest last boot's store filesystem -- no longer ephemeral, not grown
# to a resized volume, and possibly the half-written result of an interrupted
# format on a mount the guest's stage 1 cannot boot without. Formatting the store
# first makes the one leg that must happen on every boot independent of the one
# leg that is allowed to refuse.
#
# ...and it is done AT MOST ONCE PER HOST BOOT, latched on a /run marker, which
# is a second and independent safety property from the ordering above.
# RemainAfterExit keeps this unit from re-running only while it is `active`; in
# the `failed` state -- which the pool probe's own refusal above produces, with
# BOTH logical volumes already carved and active -- a plain `systemctl start
# cogworx-guest-disk` (the obvious operator retry of a failed unit) re-runs it,
# and `mkfs.ext4 -F` refuses only a MOUNTED device while this host mounts
# neither. That is a live guest's /nix/store overlay upper recreated underneath
# it. The marker closes it, and WHERE it is armed is the whole of the closure:
# the FIRST thing the script does, above the device check and above every probe.
#
# THE INVARIANT IS ABOUT THIS UNIT'S START JOB, and about nothing on the disk.
# /run is a tmpfs the host clears at boot, so an absent marker proves that no
# start job of this unit has completed this host boot; cogworx-supervisor is
# After= this unit, so supervise.sh leg (e2) -- the gate that decides whether a
# guest is launched at all -- has therefore never run, and nothing can be
# holding the store volume. A present marker means a guest may.
#
# It has to be stated that way, rather than in terms of the volume group, because
# THIS UNIT IS NOT THE ONLY THING THAT ACTIVATES IT -- which is what an earlier
# version of this comment got wrong, and the mistake was load-bearing.
# `services.lvm.enable` is true on this host, which puts lvm2 in
# `services.udev.packages`, and /etc/lvm/lvm.conf is `config {}` so
# `event_activation` keeps its default 1. lvm2's own 69-dm-lvm.rules therefore
# fires off the disk's uevent and runs `systemd-run --no-block ... lvm vgchange
# -aay cogworx-guest`, independently of this unit and before it -- it keeps
# DefaultDependencies, so it starts after basic.target -- has run a line. On an
# already-carved instance BOTH device nodes come from UDEV. So "marker absent"
# never meant "no guest can exist"; it only ever meant "no run of this script
# reached its own vgchange", and a latch armed there was absent in precisely the
# state it exists for: a run that exited at an earlier refusal, a guest leg (e2)
# then launched on the udev-created nodes, and the operator retry this unit's own
# message invites reformatting the store volume underneath it. What arming the
# latch at the top costs instead is spelled out at the arming site.
#
# Both signature probes read the device directly rather than the udev cache, so a
# stale cache entry cannot make a formatted disk look blank.
{ config, lib, pkgs, ... }:
let
	cfg = config.cogworx.gce;
	# The volume group and the two logical volumes, and the filesystem LABELS the
	# guest resolves the volumes through. Hard-coded rather than derived from
	# cfg.guestDevice, and deliberately not options: these strings answer a
	# different question from guestDevice and only happen to share a spelling.
	# guestDevice is how THIS host finds the disk (the provider's attached-disk
	# deviceName); these are how the GUEST finds the two volumes on it (cc-sandbox's
	# flake.nix `hostedVG` / `hostedPoolLV` / `hostedStoreLV` / `poolLabel` /
	# `storeOverlayLabel`, which microvm.nix turns into the volumes'
	# device = /dev/disk/by-label/<label>). An operator pointing guestDevice
	# somewhere else -- the behaviour check does exactly that -- must not thereby
	# change the names the guest is looking for. They also appear verbatim in the
	# gce-image-guest-disk-format check, same as state-disk.nix's mount unit name.
	guestVG = "cogworx-guest";
	poolLV = "pool";
	storeLV = "store";
	guestLabel = "cogworx-guest";
	storeLabel = "cogworx-store-rw";
in
{
	config = {
		# libdevmapper shells out to modprobe when /dev/mapper/control is absent,
		# and a NixOS host is not a shape to rely on that finding one. Declaring the
		# module is a line; discovering the fallback does not fire is a boot with no
		# volume group and therefore an instance that cannot start. The behaviour
		# check cannot catch this -- it loads dm_mod itself through vmTools'
		# rootModules -- so it is asserted here instead of tested there.
		boot.kernelModules = [ "dm-mod" ];

		systemd.services.cogworx-guest-disk = {
			description = "Carve, grow and format the per-instance guest data pool";
			# Deliberately NOT wantedBy anything, for the same reason
			# cogworx-state-disk is not: it runs exactly when something is about
			# to need the pool, and not at all on a boot class that has no guest
			# disk. There the puller is the mount unit's x-systemd.requires=.
			# Here there IS no host mount unit to hang that off -- the host must
			# never mount this disk -- so the puller is the supervisor, below.
			after = [ "local-fs-pre.target" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				# EXPLICIT, because the default here is NO TIMEOUT AT ALL.
				# systemd.service(5) on TimeoutStartSec=: "Defaults to
				# DefaultTimeoutStartSec= set in the manager, except when Type=oneshot
				# is used, in which case the timeout is DISABLED by default." The
				# footnote below claims a bound caps how long a wedged probe can hold
				# the VM launch; without this line that claim is simply false, and a
				# provider disk whose reads block in D-state rather than failing fast
				# -- a stalled attachment, not the fast-EIO dm-error shape the
				# behaviour check exercises -- makes the `dd` probe never return. The
				# oneshot's start job never completes, cogworx-supervisor is After=
				# this unit so its start job never runs, and the instance sits in
				# Booting forever with nothing in `systemctl --failed`: the exact
				# stuck-in-Booting mode this whole design is written against.
				#
				# 10 minutes is the sum of the bounded legs with room to spare -- two
				# 30s udevadm settles, then lvm metadata writes and two ext4 mkfs runs
				# that finish in seconds (mke2fs defaults to lazy_itable_init, so the
				# cost does not scale with the volume). Anything past that is a fault,
				# not slow progress. Being killed at the deadline is SAFE for the same
				# reason a host crash mid-mkfs is: the store volume is re-formatted
				# unconditionally on the next boot, and the pool volume is re-probed by
				# the same three-probe test, which either finds it provably blank and
				# finishes the interrupted mkfs or finds a signature and refuses. And
				# it fails the way the design already wants -- loudly, in `systemctl
				# --failed`, while the supervisor's Wants= (not Requires=) lets the
				# launch proceed and a later supervisor start retries it.
				TimeoutStartSec = 600;
				ExecStart = "${pkgs.writeShellApplication {
					name = "cogworx-guest-disk";
					runtimeInputs = [ pkgs.util-linux pkgs.e2fsprogs pkgs.coreutils pkgs.systemd pkgs.lvm2 ];
					text = ''
						dev=${cfg.guestDevice}
						vg=${guestVG}
						poollv=${poolLV}
						storelv=${storeLV}
						pooldev=/dev/${guestVG}/${poolLV}
						storedev=/dev/${guestVG}/${storeLV}
						# The store volume's configured size, twice: as an lvm size
						# argument and as bytes, so the "is it already big enough?"
						# comparison never has to parse an lvm-formatted number.
						storesize=${toString cfg.storeOverlaySizeMiB}m
						storebytes=${toString (cfg.storeOverlaySizeMiB * 1048576)}

						# ===== the once-per-host-boot LATCH, armed FIRST ===============
						# Above the device check, above every probe, above the
						# volume-group activation -- because of what this marker has to
						# MEAN. /run is a tmpfs the host clears at boot, so an absent
						# marker has to prove that no guest can be holding the store
						# volume open. Armed here it proves exactly that, by a route that
						# does not depend on this script's own progress at all:
						# cogworx-supervisor is Wants= + After= this unit, so its start
						# job cannot run until this unit's start job COMPLETES, and
						# supervise.sh leg (e2) -- which decides whether `cogbox start` is
						# called -- is inside it. "Marker absent" therefore means "no start
						# job of this unit has completed this host boot", which means leg
						# (e2) has never run, which means there is no guest.
						#
						# ARMED ANY LATER, THAT IS FALSE ON THE SHIPPED IMAGE. It used to
						# be armed at `lvmc vgchange -ay` below, reasoning that the
						# activation is the earliest moment a guest can exist because leg
						# (e2) tests only that the two volume device NODES are block
						# devices and that vgchange is what creates them. THIS UNIT IS NOT
						# THE ONLY ACTIVATOR: `services.lvm.enable` is true on this host,
						# which puts lvm2 in `services.udev.packages`, and /etc/lvm/lvm.conf
						# is `config {}` so `event_activation` keeps its default 1 -- so
						# lvm2's 69-dm-lvm.rules fires off the disk's own uevent and runs
						# `systemd-run --no-block ... lvm vgchange -aay ${guestVG}`,
						# independently of this unit and before it (DefaultDependencies
						# kept, so it starts after basic.target) has run a line. On an
						# already-carved instance both nodes exist before this script
						# starts. Any run that then ended early -- a transient read error
						# at the probe below, an `lvmc pvs` or `vgchange` that failed, a
						# TimeoutStartSec kill on a wedged probe -- left the marker absent
						# while leg (e2) was perfectly happy to launch a guest that mounts
						# the store volume read-write as its /nix/store overlay upper. The
						# retry this unit's own failure message invites (`systemctl start
						# cogworx-guest-disk`) then found no marker and ran `mkfs.ext4 -F`
						# on that live volume -- -F refuses only a MOUNTED device and this
						# host mounts neither -- destroying the running sandbox's whole
						# /nix/store upper mid-session, and exited 0 with nothing in
						# `systemctl --failed`. REPRODUCED; case 14 of
						# gce-image-guest-disk-behaviour is that chain.
						#
						# THE COST, accepted deliberately and wider than it was: EVERY run
						# that ends before the store leg -- the four refusals below, the
						# absent-device exit 0, a kill at TimeoutStartSec -- now leaves the
						# store filesystem NOT re-made this host boot, so a retry runs the
						# guest on last boot's: stale, and not grown to a volume somebody
						# just resized. That is survivable by construction -- the store
						# overlay upper holds no user data and the next host boot (a Stop
						# -> Start) re-makes it. On a FIRST-EVER carve there is no last
						# boot's filesystem to fall back to, so the same retry leaves the
						# guest a store volume with NO filesystem, and its stage-1 mount by
						# label then cannot succeed for the rest of this host boot. That
						# cost is accepted too -- no user data is anywhere near it and a
						# Stop -> Start recovers it -- but only because it is LOUD, and
						# MEASURED it was not: skipping the mkfs simply ran off the end of
						# the script and exited 0, leaving this unit `active` and nothing
						# in `systemctl --failed`. So the store leg PROBES what it is
						# skipping and fails by name when there is no labelled filesystem
						# there to skip re-making. Every one of these is recoverable;
						# reformatting under a live guest is not.
						#
						# Test-and-set rather than a bare `: >`: the store leg has to know
						# whether THIS run is the one that armed it, or the first run of
						# every host boot would skip the format it is the whole point of.
						storeflag=/run/cogworx-guest-disk.store-formatted
						storedone=0
						if [ -e "$storeflag" ]; then
							storedone=1
						else
							: > "$storeflag"
						fi

						# EVERY lvm call goes through this, and the --devices scoping is
						# the point of it. It restricts the command to this one disk, so
						# nothing here can see, activate, rename or resize a physical
						# volume anywhere else on the host -- including a volume group
						# that happened to be named the same on another disk, which is
						# the only way a name-scoped command could have gone wrong.
						# (--devices needs no devices FILE: this lvm2 builds with
						# use_devicesfile=0, so the flag simply narrows the device set
						# for the duration of the call and leaves no state behind.)
						lvmc() {
							local sub=$1
							shift
							lvm "$sub" --devices "$dev" "$@"
						}

						# The three-probe blankness test, as a function because it is
						# applied TWICE: to the raw disk before the volume group is
						# created, and to the pool logical volume before its mkfs. See
						# the header for why one probe -- or two blind ones -- cannot
						# establish blankness.
						#
						#   0  provably blank: a read that SUCCEEDED, then refuted by
						#      neither signature probe.
						#   1  not blank, or not provably so. probe_type carries blkid's
						#      TYPE (empty when it had none) and probe_why the evidence.
						#   2  the device could not be READ. Distinct from 1 because it
						#      is a fault rather than a state.
						probe_type=""
						probe_why=""
						probe_blank() {
							local d=$1 rc=0 wrc=0 ptype psigs
							# 1 MiB is not an attempt to duplicate libblkid's coverage;
							# it spans the superblock offsets it checks near the start
							# (xfs at 0, ext* at 1 KiB, btrfs at 64 KiB, LVM's PV label in
							# the first four sectors) and the point is only that this
							# device reads.
							if ! dd if="$d" of=/dev/null bs=1M count=1 status=none; then
								probe_type=""
								probe_why="the device could not be read"
								return 2
							fi
							# `|| rc=$?` rather than an `if` around either probe, because
							# the exit STATUS is load-bearing here and not just the
							# presence of output. set -e does not fire inside a || list.
							ptype=$(blkid -p -o value -s TYPE "$d" 2>/dev/null) || rc=$?
							# A second signature probe, independent of blkid's TYPE
							# lookup: wipefs enumerates EVERY magic string it knows,
							# partition tables included, so a disk carrying something
							# blkid does not surface as a TYPE is still refused.
							# --no-act writes nothing; -i drops the column heading so an
							# empty result really is an empty string; stderr is KEPT (no
							# 2>/dev/null) because it is where wipefs says why it could
							# not look, and its nonzero exit covers the could-not-OPEN
							# case (measured: exit 1 and "probing initialization failed",
							# where blkid returns a silent exit 2).
							psigs=$(wipefs --no-act -i -O TYPE "$d") || wrc=$?
							probe_type=$ptype
							if [ "$rc" -ne 2 ] || [ -n "$ptype" ] || [ "$wrc" -ne 0 ] || [ -n "$psigs" ]; then
								probe_why="blkid exit $rc type '$ptype'; wipefs exit $wrc signatures '$(echo "$psigs" | tr "\n" " ")'"
								return 1
							fi
							probe_why=""
							return 0
						}

						# Size helpers. --units b --nosuffix yields plain integers, so
						# nothing here has to parse a locale-dependent decimal. Empty
						# becomes 0 rather than propagating: an lvm query that failed must
						# read as "no room", which is the direction that refuses to write.
						lv_bytes() {
							local v=""
							v=$(lvmc lvs --noheadings --units b --nosuffix -o lv_size "$vg/$1" 2>/dev/null | tr -d '[:space:]') || v=""
							if [ -z "$v" ]; then v=0; fi
							printf '%s' "$v"
						}
						vg_free_bytes() {
							local v=""
							v=$(lvmc vgs --noheadings --units b --nosuffix -o vg_free "$vg" 2>/dev/null | tr -d '[:space:]') || v=""
							if [ -z "$v" ]; then v=0; fi
							printf '%s' "$v"
						}
						lv_missing() {
							! lvmc lvs --noheadings -o lv_name "$vg/$1" >/dev/null 2>&1
						}

						# /dev/disk/by-id/google-* is a udev SYMLINK, created
						# asynchronously by a rule rather than by the kernel event that
						# enumerates the disk. Without this the first boot of a fresh
						# instance can lose the race, take the absent-device branch
						# below, and leave the disk uncarved. settle is bounded and, on a
						# boot class with no guest disk, free: the udev queue is already
						# empty there, so it returns immediately rather than waiting out
						# the timeout.
						udevadm settle --timeout=30 || \
							echo "cogworx-guest-disk: udevadm settle did not drain cleanly; probing $dev anyway"

						# ===== the device is ABSENT =====================================
						if [ ! -b "$dev" ]; then
							# Not an error HERE, and not silent. A resolver VM boots this
							# same image with no guest disk attached and must reach
							# multi-user.target; this unit runs on every boot class and
							# cannot tell that one from a sandbox whose disk failed to
							# attach, so it does not guess. The sandbox case is caught by
							# supervise.sh leg (e2), which runs only on a boot that is
							# about to start a guest and fatals by name on the missing
							# volume. That split is why this is the one refusal below
							# that still exits 0.
							echo "cogworx-guest-disk: $dev is not attached; nothing to initialise (a boot that needs it fails at cogworx-supervisor leg e2 instead)"
							exit 0
						fi

						# ===== classify the disk =======================================
						blank=0
						probe_blank "$dev" || blank=$?
						if [ "$blank" = 2 ]; then
							# ===== the device is UNREADABLE ============================
							# exit 1, not 0: an attached disk that will not read is a
							# FAULT, not a boot class, and it should show up in
							# `systemctl --failed`. It costs nothing -- the supervisor
							# only Wants= this unit -- and a later supervisor start
							# retries it, so a transient error self-heals.
							echo "cogworx-guest-disk: $dev cannot be READ; refusing to touch a disk this host could not examine" >&2
							exit 1
						elif [ "$blank" = 0 ]; then
							# ===== the device is BLANK ================================
							echo "cogworx-guest-disk: $dev is provably blank; creating physical volume and volume group $vg"
							lvmc pvcreate --yes "$dev"
							lvmc vgcreate --yes "$vg" "$dev"
						elif [ "$probe_type" = LVM2_member ]; then
							# ===== the device is ALREADY LVM ==========================
							# The steady state: every boot after the first. Nothing is
							# created; the volume group is activated and grown below.
							echo "cogworx-guest-disk: $dev already carries LVM metadata; not re-creating anything"
						else
							# ===== NON-LVM FILESYSTEM, or WE CANNOT TELL ==============
							# exit 1, not 0. The refusal is unchanged -- nothing is
							# written to a disk this host does not understand -- but with
							# one baked storage profile this boot yields NO guest, and
							# exiting 0 left the unit `active` with nothing in `systemctl
							# --failed` while the supervisor flapped. A refusal that
							# costs the user their sandbox has to be a failed unit.
							echo "cogworx-guest-disk: $dev is not PROVABLY blank and is not an LVM physical volume ($probe_why); leaving it alone" >&2
							exit 1
						fi

						# The volume group this disk actually belongs to, read back rather
						# than assumed. Three outcomes, and the middle one is a real
						# self-heal: a pvcreate that succeeded and a vgcreate that did not
						# leaves an orphan physical volume, which holds nothing and is
						# safe to complete. A DIFFERENT volume group is somebody else's
						# disk and is left exactly as it is -- renaming it to make it fit
						# here is the opposite of every guard above.
						found=$(lvmc pvs --noheadings -o vg_name "$dev" 2>/dev/null | tr -d '[:space:]' || true)
						if [ -z "$found" ]; then
							echo "cogworx-guest-disk: $dev is a physical volume with no volume group (an interrupted first initialisation); creating $vg"
							lvmc vgcreate --yes "$vg" "$dev"
						elif [ "$found" != "$vg" ]; then
							# exit 1, same visibility argument as the foreign-filesystem
							# branch above: the group is left untouched, but this boot has
							# no volumes for QEMU and therefore no guest, so it must be a
							# failed unit rather than a warning nobody reads.
							echo "cogworx-guest-disk: WARNING $dev carries volume group '$found', not $vg; the guest will not find its volumes and this host will not rename somebody else's group" >&2
							exit 1
						fi

						# ===== activate, then GROW =====================================
						# Order matters and it is the whole of decision 5: this unit is
						# ordered before cogworx-supervisor, which is what launches the
						# guest, so the volumes are already at their new size by the time
						# QEMU opens them. Growing after the launch would leave the guest
						# sized to the old disk until the boot after next.
						# Frequently a NO-OP, and that is the point of the latch above:
						# lvm2's 69-dm-lvm.rules has usually already run `vgchange -aay`
						# off the disk's uevent by the time this unit starts. This call is
						# what guarantees the volumes are up on the boot classes where udev
						# did not (a group that appeared before the rules were loaded, a
						# disk attached after the uevent was processed), not what makes the
						# device nodes exist for the first time in the general case.
						lvmc vgchange -ay "$vg" >/dev/null

						# The operator grew the provider disk; teach the physical volume
						# about the new end. Idempotent by construction -- a pvresize with
						# nothing to add is a successful no-op. Its output is deliberately
						# NOT swallowed: this is the leg that makes restart-to-grow happen,
						# and one line per boot saying whether the physical volume changed
						# is the only evidence an operator has that a disk they grew was
						# picked up.
						lvmc pvresize "$dev"

						# SIZING POLICY, in two lines and in this order: the store overlay
						# takes its CONFIGURED size, the pool takes the REMAINDER. Doing
						# the store first is what makes that true; doing the pool first
						# would leave the store nothing to grow into.
						#
						# Every extend is guarded on free extents rather than attempted
						# and tolerated, because `lvextend` with nothing to add exits 5
						# ("matches existing size") and this unit must be a clean no-op on
						# an already-initialised disk that nobody grew.
						if lv_missing "$storelv"; then
							free=$(vg_free_bytes)
							if [ "$free" -le "$storebytes" ]; then
								# Refuse rather than half-carve. A store volume that ate
								# the whole group would leave the user's pool with nothing,
								# and an instance that starts and then has no pool is worse
								# than one that does not start: the second is a deployment
								# error an operator can see and fix by growing the disk.
								echo "cogworx-guest-disk: $vg has $free bytes free, which cannot hold a $storesize store overlay AND a data pool; refusing to carve either" >&2
								exit 1
							fi
							echo "cogworx-guest-disk: creating the $storesize store overlay volume"
							lvmc lvcreate --yes -L "$storesize" -n "$storelv" "$vg"
						else
							have=$(lv_bytes "$storelv")
							if [ "$have" -lt "$storebytes" ]; then
								free=$(vg_free_bytes)
								if [ "$free" -ge $(( storebytes - have )) ]; then
									echo "cogworx-guest-disk: growing the store overlay volume to $storesize"
									lvmc lvextend -L "$storesize" "$vg/$storelv"
								else
									echo "cogworx-guest-disk: WARNING the store overlay volume is $have bytes and the configured size is $storebytes, but only $free bytes are free; leaving it as it is" >&2
								fi
							fi
							# NOT shrunk when the configured size goes DOWN. lvreduce on a
							# volume whose filesystem is larger truncates it, and the
							# operator who lowered a number in a module did not ask for
							# that; the store volume simply stays where it is until the
							# instance is recreated.
						fi

						if lv_missing "$poollv"; then
							free=$(vg_free_bytes)
							if [ "$free" -le 0 ]; then
								echo "cogworx-guest-disk: $vg has no free space for the data pool volume; the guest cannot start without it" >&2
								exit 1
							fi
							echo "cogworx-guest-disk: creating the data pool volume from the remaining $free bytes"
							lvmc lvcreate --yes -l 100%FREE -n "$poollv" "$vg"
						else
							free=$(vg_free_bytes)
							if [ "$free" -gt 0 ]; then
								echo "cogworx-guest-disk: growing the data pool volume by the remaining $free bytes"
								lvmc lvextend -l +100%FREE "$vg/$poollv"
							fi
						fi

						# The device nodes are what QEMU opens, and lvm creates them
						# asynchronously through its udev rules where udev is running. A
						# second settle plus an explicit block-device test is the
						# difference between a clear failure here and QEMU failing to open
						# a drive three units later.
						udevadm settle --timeout=30 || \
							echo "cogworx-guest-disk: udevadm settle did not drain cleanly after activation"
						for d in "$pooldev" "$storedev"; do
							if [ ! -b "$d" ]; then
								echo "cogworx-guest-disk: $d is not a block device after activation; the guest could not open it" >&2
								exit 1
							fi
						done
						# One line per boot naming what the guest is about to be handed.
						# The alternative is an operator asking "how big is this sandbox's
						# pool?" and having to shell into the host to find out; a disk that
						# was grown and a disk that was not look identical without it.
						echo "cogworx-guest-disk: data pool $pooldev is $(lv_bytes "$poollv") bytes, store overlay $storedev is $(lv_bytes "$storelv") bytes, $(vg_free_bytes) bytes unallocated in $vg"

						# ===== the STORE volume's filesystem, UNCONDITIONAL ============
						# Re-created on every host boot, and that is deliberate three
						# times over (see the header): it keeps the writable /nix/store
						# overlay exactly as ephemeral as the tmpfs it replaces, it
						# self-heals an interrupted mkfs on a volume the guest's stage 1
						# cannot boot without, and it is how this volume GROWS, since
						# x-systemd.growfs cannot run for a neededForBoot mount.
						#
						# BEFORE the pool probe, not after it, because that probe is
						# allowed to refuse and this leg is not allowed to be skipped.
						# Behind it, an unreadable pool volume -- which exits 1 with both
						# device NODES present, so QEMU opens both drives and the guest
						# boots regardless -- silently handed the guest last boot's store
						# filesystem. See the header.
						#
						# Safe to write unconditionally because of WHAT it is, not because
						# of what it looks like: a store overlay upper holds no user data,
						# and the target is a logical volume this unit carved inside a
						# volume group it verified is on this instance's own disk. -F
						# because mkfs would otherwise prompt about the filesystem it is
						# replacing.
						#
						# ...but ONCE PER HOST BOOT, and that bound is not what
						# RemainAfterExit gives. RemainAfterExit suppresses a re-run only
						# while the unit is `active`; everything above is ALLOWED to fail --
						# the four refusals, the pool probe below, and any leg killed at
						# TimeoutStartSec -- and on an already-carved instance lvm2's udev
						# rule has already activated the volume group, so BOTH device nodes
						# are present however early this script gave up. That is exactly
						# when the supervisor (Wants=, not Requires=) launches a guest on
						# them. From there a plain `systemctl start cogworx-guest-disk` --
						# the obvious operator retry of a failed unit, and the same thing
						# the supervisor's own Restart=always does to the Wants= job --
						# re-enters here and recreates the filesystem under a LIVE guest
						# holding it open. `-F` does not save us: it refuses a MOUNTED
						# device, and this host mounts neither volume by design.
						#
						# Which is why the marker is armed on the script's FIRST lines and
						# only READ here. It cannot be armed on this line, and it cannot be
						# armed at the vgchange either: `After=` is satisfied by a failed
						# start job too, leg (e2) gates the launch on the volume device
						# NODES alone, and on an already-carved instance UDEV -- not this
						# unit -- is what created them. See the arming site for the
						# invariant, for the other activator, and for what arming that early
						# costs.
						if [ "$storedone" = 1 ]; then
							echo "cogworx-guest-disk: NOT (re)formatting $storedev: another run of this unit already started in this host boot, so cogworx-supervisor may have launched a guest that holds it open. It is recreated on the next host boot." >&2
							# SKIPPED is not the same as FINE, and the difference is the
							# whole of what the arming site accepts as a cost. A retry
							# after an interrupted FIRST carve arrives here with no store
							# filesystem to have skipped re-making, and the guest resolves
							# this volume BY LABEL on its stage-1 path (neededForBoot,
							# x-initrd.mount, no nofail) -- so a missing or
							# differently-labelled filesystem is an instance that cannot
							# boot at all for the rest of this host boot. Formatting it
							# here is the one thing that is still not allowed, so the exit
							# STATUS is the only lever left: MEASURED, falling through
							# exited 0 and left this unit `active`, nothing in `systemctl
							# --failed` and the supervisor flapping with no unit saying
							# why, which is the mode this file exists to prevent. Nothing
							# is written either way; only the reporting changes.
							# `|| true` on both, because blkid exits nonzero on a volume
							# carrying no signature at all -- exactly the case being
							# tested for -- and this script runs under set -e.
							storetype=$(blkid -p -o value -s TYPE "$storedev" 2>/dev/null || true)
							storelabel=$(blkid -p -o value -s LABEL "$storedev" 2>/dev/null || true)
							if [ -z "$storetype" ] || [ "$storelabel" != ${storeLabel} ]; then
								echo "cogworx-guest-disk: $storedev has no ${storeLabel} filesystem (type '$storetype', label '$storelabel') and this run must not create one, because another run of this unit already started in this host boot; the guest's stage-1 mount resolves this volume by label and cannot start without it. Stop and Start this instance: the next host boot clears the marker and re-makes the filesystem." >&2
								exit 1
							fi
						else
							echo "cogworx-guest-disk: (re)creating ext4 labelled ${storeLabel} on $storedev"
							mkfs.ext4 -q -F -L ${storeLabel} "$storedev"
						fi

						# ===== the POOL volume's filesystem, GUARDED ===================
						# The same three probes as the disk, for the same reason: this
						# volume holds the user's only copy of their work tree, and the
						# ONLY boot that may write a filesystem here is the one after the
						# lvcreate that made it.
						poolblank=0
						probe_blank "$pooldev" || poolblank=$?
						if [ "$poolblank" = 2 ]; then
							echo "cogworx-guest-disk: $pooldev cannot be READ; refusing to format a volume this host could not examine" >&2
							exit 1
						elif [ "$poolblank" = 0 ]; then
							echo "cogworx-guest-disk: $pooldev is unformatted; creating ext4 labelled ${guestLabel}"
							mkfs.ext4 -q -L ${guestLabel} "$pooldev"
						else
							echo "cogworx-guest-disk: $pooldev already holds a filesystem ($probe_why); leaving it alone"
							# The guest resolves this volume BY LABEL, so an ext4 with no
							# label at all is a pool the guest cannot mount. Naming it is
							# pure superblock metadata -- e2label touches no file data --
							# and it is the one repair that is safe to make to a volume we
							# have just refused to format. A volume carrying a DIFFERENT
							# label is left exactly as it is and merely reported.
							if [ "$probe_type" = ext4 ]; then
								label=$(blkid -p -o value -s LABEL "$pooldev" 2>/dev/null || true)
								if [ -z "$label" ]; then
									echo "cogworx-guest-disk: labelling the existing filesystem ${guestLabel} so the guest can resolve it"
									e2label "$pooldev" ${guestLabel}
								elif [ "$label" != ${guestLabel} ]; then
									echo "cogworx-guest-disk: WARNING $pooldev is labelled '$label', not ${guestLabel}; the guest will not find it and this host will not rename it" >&2
								fi
							fi
						fi
					'';
				}}/bin/cogworx-guest-disk";
			};
		};

		# NO fileSystems entry, and that absence is the design. The host must
		# never mount the guest's pool; gce-image-guest-disk-format asserts the
		# realized host fstab has no entry for the device at all.
		#
		# Which means the ordering cannot be expressed the way state-disk.nix
		# expresses it. There the mount unit is the seam: it Requires= the format
		# service and is itself ordered x-systemd.before= every consumer. With no
		# mount unit, the thing that must not overtake this unit is the VM LAUNCH
		# -- cogworx-supervisor.service is what runs supervise.sh, which runs
		# `cogbox start`, which hands QEMU these devices. Two things ride on that
		# ordering: mkfs racing a running guest is the one way this file could
		# still corrupt live data, and a grow that lands after the launch would
		# leave the guest sized to the old disk for a whole session.
		#
		# `wants`, NOT `requires`, and the asymmetry is deliberate in both
		# directions:
		#   - Wants is what PULLS the unit in. It is the only thing that does
		#     (nothing else wants it, see above), so the supervisor being
		#     wantedBy multi-user.target is what makes this run at boot, and a
		#     later `systemctl start cogworx-supervisor` re-enqueues it if it is
		#     not already active -- so a failed carve is retried on the next
		#     supervisor start rather than being latched off.
		#   - Requires would make a failed or timed-out carve prevent the sandbox
		#     from starting AT ALL, and the bounded case matters too: the
		#     TimeoutStartSec set on the unit above caps how long a wedged probe
		#     can hold the launch, and with Wants the launch then proceeds instead
		#     of failing with it. Note that the bound is the EXPLICIT setting and
		#     nothing else -- a Type=oneshot unit has NO start timeout by default
		#     (systemd.service(5)), so leaving it off would let a blocked read hold
		#     the VM launch indefinitely, with `Wants` buying nothing because it
		#     does not weaken `After`.
		# After is what actually orders them: for a Type=oneshot unit the start
		# job is not complete until ExecStart exits, so the supervisor cannot
		# reach `cogbox start` while lvm or mkfs is still running. RemainAfterExit
		# is HALF of the other safety property -- a unit that succeeded stays
		# active for the rest of the boot, so the supervisor's own Restart=always
		# cannot re-trigger the store volume's mkfs underneath a live guest. Only
		# half, because a unit that FAILED is re-enqueued by that same Wants=
		# edge; the other half is the /run marker the carve script arms on its
		# very first lines. The consequence is that both the carve and the
		# grow happen once per HOST boot, which is exactly decision 5's Stop ->
		# resize the disk -> Start.
		#
		# FAILURE HANDLING, in TWO layers, because moving the volumes behind LVM
		# split the failure set in half and only one half is reachable from inside
		# the guest.
		#
		# Once the volumes EXIST, the guest's own layer handles it: the pool mount
		# is `nofail` and every pool-backed bind Requires= it, so a pool whose
		# first mkfs did not finish, a label that does not resolve or a filesystem
		# that will not mount costs the binds and not the boot. That is not a
		# second storage MODE -- see the nofail note in flake.nix, which is about
		# the guest coming up far enough to REPORT a fault the host cannot see.
		#
		# The other half is the four cases this unit REFUSES (absent, unreadable,
		# foreign filesystem, foreign volume group). There are then no logical
		# volumes at all, no amount of `nofail` inside the guest helps, and this
		# image has nothing else to launch: both volumes are autoCreate = false, so
		# QEMU is handed two paths that do not exist and `cogbox start` fails.
		# THAT OUTCOME IS ACCEPTED. What is not accepted is the shape it used to
		# have -- a supervisor flapping under Restart=always with nothing in
		# `systemctl --failed` and only "sandbox start failed" on serial, i.e. an
		# instance in "Booting" that nobody can diagnose. Three things make it
		# diagnosable now, and all three are load-bearing:
		#
		#   - three of the four refusals exit 1, so this unit lands in `systemctl
		#     --failed` naming the disk and the reason (the fourth, an absent
		#     device, is a legitimate resolver boot class and cannot be judged
		#     here);
		#   - supervise.sh leg (e2) tests the volume device nodes before the launch
		#     and fatals by NAME onto serial, which is the channel the control
		#     plane reads on a VM whose guest never came up;
		#   - and the HOST half is untouched by every one of them -- no fileSystems
		#     entry, Wants= rather than Requires= on the supervisor, a finite
		#     TimeoutStartSec above -- so sshd and the control channel answer
		#     throughout. A guest that will not launch is survivable; an
		#     unreachable VM is not.
		#
		# Refusing to touch a disk we do not understand stays exactly as strict as
		# it was. What changed is that the refusal is now loud in three places
		# instead of being papered over by a second guest profile.
		systemd.services.cogworx-supervisor = {
			wants = [ "cogworx-guest-disk.service" ];
			after = [ "cogworx-guest-disk.service" ];
		};
	};
}
