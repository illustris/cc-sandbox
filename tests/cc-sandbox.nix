{ self, pkgs, system }:

{
	name = "cc-sandbox-vm";

	nodes.machine = { config, lib, ... }: {
		virtualisation = {
			cores = 4;
			memorySize = 8192;
			diskSize = 8192;
			qemu.options = [ "-cpu" "host" ];
		};

		boot.kernelModules = [ "kvm-intel" "kvm-amd" ];

		environment.systemPackages = with pkgs; [
			self.packages.${system}.cc-sandbox
			openssh
			jq
			netcat-openbsd
		];

		users.users.testuser = {
			isNormalUser = true;
			home = "/home/testuser";
			password = "";
			extraGroups = [ "kvm" ];
		};

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
