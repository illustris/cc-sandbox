{ self, pkgs, system }:

let
	# Recursively collect every transitive flake input source path. Phase E
	# triggers cogbox's wrapper to re-eval its own flake on the test
	# machine; nix resolves locked inputs by checking /nix/store for a path
	# whose narHash matches the lock entry, so pinning every input (direct
	# and transitive) into the system closure is enough to make the eval
	# work offline. Direct inputs alone are not sufficient: e.g. nix-mcp
	# pulls in numtide/flake-utils, which would otherwise be refetched.
	collectFlakeInputs = let
		walk = input: [ input ] ++ (
			if (builtins.isAttrs input && input ? inputs)
			then builtins.concatMap walk (builtins.attrValues input.inputs)
			else []
		);
	in inputs: builtins.concatMap walk (builtins.attrValues inputs);
in {
	name = "cogbox-vm";

	nodes.machine = { config, lib, ... }: {
		virtualisation = {
			cores = 4;
			memorySize = 8192;
			diskSize = 8192;
			qemu.options = [ "-cpu" "host" ];
		};

		boot.kernelModules = [ "kvm-intel" "kvm-amd" ];

		environment.systemPackages = with pkgs; [
			self.packages.${system}.cogbox
			openssh
			jq
			netcat-openbsd
			# Phase E rebuilds the inner microvm runner with pkgs.hello in
			# the closure. Pre-realize it on the outer machine so the inner
			# nix build resolves it from the local store with no fetch.
			hello
		];

		# Pin all transitive flake-input sources into the test machine's
		# /nix/store so the wrapper's `nix run` re-eval (Phase E) can
		# resolve every locked input via narHash lookup, with no network.
		# Also pin the pre-built runner *and the wrapper script* whose
		# .drv hashes match what Phase E produces at runtime; without
		# either, nix would attempt to (re)build the transitive .drv
		# graph -- ~thousands of derivations including the stage0-posix
		# bootstrap chain -- and time out fetching tarballs offline.
		system.extraDependencies =
			(collectFlakeInputs self.inputs)
			++ [
				self.nixosConfigurations.cogbox-x86_64-test-hello.config.microvm.declaredRunner
				self.packages.x86_64-linux.cogbox-test-hello
			];

		users.users.testuser = {
			isNormalUser = true;
			uid = 1000;
			home = "/home/testuser";
			password = "";
			extraGroups = [ "kvm" ];
		};

		# `systemd-run --uid=testuser` in the test script runs without a
		# logind session, so /run/user/1000 is never created. Pre-create
		# it so cogbox's XDG runtime path resolves to /run/user/1000
		# (matching a real interactive setup) instead of the /tmp fallback.
		systemd.tmpfiles.rules = [
			"d /run/user/1000 0700 testuser users -"
		];

		security.sudo.wheelNeedsPassword = false;

		programs.ssh.extraConfig = ''
			Host 127.0.0.1
				StrictHostKeyChecking no
				UserKnownHostsFile /dev/null
				LogLevel ERROR
		'';
	};

	testScript = builtins.readFile ./test_script.py;
}
