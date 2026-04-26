{
	description = "cc-sandbox MicroVM";

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
		nixpkgs-master.url = "github:nixos/nixpkgs?ref=master";
		illustris-lib = {
			url = "github:illustris/flake";
			flake = false;
		};
		microvm = {
			url = "github:microvm-nix/microvm.nix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
		nix-mcp = {
			url = "github:illustris/nix-mcp";
			inputs.nixpkgs.follows = "nixpkgs";
			inputs.illustris-lib.follows = "illustris-lib";
		};
		nixfs = {
			url = "github:illustris/nixfs";
			inputs.nixpkgs.follows = "nixpkgs";
			inputs.illustris-lib.follows = "illustris-lib";
		};
	};

	outputs = { self, nixpkgs, microvm, nix-mcp, ... }@inputs: let
		lib = nixpkgs.lib;
		illustris-lib = import "${inputs.illustris-lib}/lib" { inherit lib; };
		supportedSystems = [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
		forAllSystems = f: lib.genAttrs supportedSystems f;

		archSuffix = system: builtins.head (lib.splitString "-" system);
		configName = system: "cc-sandbox-${archSuffix system}";

		# Runtime symlink directory -- QEMU references these fixed paths;
		# the wrapper populates them with symlinks to user-specific locations.
		runtimeDir = "/tmp/cc-sandbox";
		dataDir = "${runtimeDir}/data";
		claudeConfigDir = "${runtimeDir}/claude-config";
		claudeAuthFile = "${runtimeDir}/claude-auth.json";

		macFromName = name: let
			hash = builtins.hashString "sha256" name;
			b = i: builtins.substring (i * 2) 2 hash;
		in "02:${b 0}:${b 1}:${b 2}:${b 3}:${b 4}";

		mkMicrovm = system: name: {
			vcpu ? 2,
			mem ? 2048,
			extraModules ? []
		}: nixpkgs.lib.nixosSystem {
			inherit system;
			modules = [
				microvm.nixosModules.microvm
				({ pkgs, ... }: {
					networking.hostName = name;
					users.users.root.password = "";
					services.getty.autologinUser = "root";
					microvm = {
						hypervisor = "qemu";
						inherit vcpu mem;
						socket = "${name}.socket";
						interfaces = [{
							type = "user";
							id = "usernet";
							mac = macFromName name;
						}];
						shares = [
							{
								proto = "9p";
								tag = "ro-store";
								source = "/nix/store";
								mountPoint = "/nix/.ro-store";
							}
							{
								proto = "9p";
								tag = "${name}-data";
								source = dataDir;
								mountPoint = "/var/lib/${name}";
							}
						];
					};
					nix = {
						nixPath = [ "nixpkgs=${pkgs.path}" ];
						settings.experimental-features = [ "nix-command" "flakes" ];
					};
					system.stateVersion = "25.11";
				})
			] ++ extraModules;
		};

		ccSandboxModules = system: let
			hasClaude = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
			hasNixMcp = builtins.hasAttr system (nix-mcp.packages or {});
		in [
			inputs.nixfs.nixosModules.nixfs
			({ pkgs, lib, ... }: let
				claude-code-bin =
					if hasClaude
					then (import inputs.nixpkgs-master {
						inherit system;
						config.allowUnfree = true;
					}).claude-code-bin
					else null;
			in {
				nixpkgs.config.allowUnfree = true;

				services.openssh.enable = true;

				systemd.services.load-ssh-keys = {
					description = "Load SSH authorized keys from shared config";
					wantedBy = [ "multi-user.target" ];
					before = [ "sshd.service" ];
					after = [ "var-lib-cc\\x2dsandbox.mount" ];
					requires = [ "var-lib-cc\\x2dsandbox.mount" ];
					serviceConfig = {
						Type = "oneshot";
						RemainAfterExit = true;
						ExecStart = pkgs.writeShellScript "load-ssh-keys" ''
							keyfile=/var/lib/cc-sandbox/.config/authorized_keys
							if [ -f "$keyfile" ] && [ -s "$keyfile" ]; then
								mkdir -p /root/.ssh
								chmod 700 /root/.ssh
								cp "$keyfile" /root/.ssh/authorized_keys
								chmod 600 /root/.ssh/authorized_keys
							fi
						'';
					};
				};

				environment.systemPackages = with pkgs; [
					git
					curl
					jq
					vim
					ncdu
					tmux
					htop
				]
				++ lib.optionals hasClaude [
					claude-code-bin
					(writeScriptBin "c" ''IS_SANDBOX=1 exec ${lib.getExe claude-code-bin} --dangerously-skip-permissions "$@"'')
				]
				++ lib.optionals hasNixMcp [
					nix-mcp.packages.${system}.default
				]
				++ lib.optionals (system != "riscv64-linux") [
					bpftrace
				];

				microvm = {
					writableStoreOverlay = "/nix/.rw-store";
					forwardPorts = [
						{ from = "host"; host.port = 2222; host.address = "127.0.0.1"; guest.port = 22; }
						{ from = "host"; host.port = 8080; host.address = "127.0.0.1"; guest.port = 8080; }
					];
					shares = [
						{
							proto = "9p";
							tag = "claude-config";
							source = claudeConfigDir;
							mountPoint = "/var/lib/claude-lower";
							readOnly = true;
						}
					];
					qemu.extraArgs = [
						"-fw_cfg"
						"name=opt/claude-auth,file=${claudeAuthFile}"
					];
				};

				systemd.services.claude-auth = {
					description = "Copy Claude auth token from fw_cfg";
					wantedBy = [ "multi-user.target" ];
					before = [ "multi-user.target" ];
					serviceConfig = {
						Type = "oneshot";
						ExecStart = "/bin/sh -c 'cp /sys/firmware/qemu_fw_cfg/by_name/opt/claude-auth/raw /root/.claude.json && chmod 600 /root/.claude.json'";
						RemainAfterExit = true;
					};
				};

				systemd.services.claude-overlay-img = {
					description = "Create ext4 image for Claude overlay";
					wantedBy = [ "var-lib-claude\\x2drw.mount" ];
					before = [ "var-lib-claude\\x2drw.mount" ];
					after = [ "var-lib-cc\\x2dsandbox.mount" ];
					requires = [ "var-lib-cc\\x2dsandbox.mount" ];
					unitConfig.DefaultDependencies = false;
					serviceConfig = {
						Type = "oneshot";
						RemainAfterExit = true;
						ExecStart = pkgs.writeShellScript "claude-overlay-img" ''
							img=/var/lib/cc-sandbox/claude-overlay.img
							if [ ! -f "$img" ]; then
								size="128M"
								sizefile=/var/lib/cc-sandbox/.config/overlay-size
								if [ -f "$sizefile" ]; then
									size=$(cat "$sizefile")
								fi
								${pkgs.coreutils}/bin/truncate -s "$size" "$img"
								${pkgs.e2fsprogs}/bin/mkfs.ext4 -q "$img"
							fi
						'';
					};
				};

				systemd.services.resize-store-overlay = {
					description = "Resize writable nix store overlay from config";
					wantedBy = [ "multi-user.target" ];
					after = [ "var-lib-cc\\x2dsandbox.mount" ];
					requires = [ "var-lib-cc\\x2dsandbox.mount" ];
					serviceConfig = {
						Type = "oneshot";
						RemainAfterExit = true;
						ExecStart = pkgs.writeShellScript "resize-store-overlay" ''
							sizefile=/var/lib/cc-sandbox/.config/store-overlay-size
							if [ -f "$sizefile" ]; then
								size=$(cat "$sizefile")
								${pkgs.util-linux}/bin/mount -o "remount,size=$size" /nix/.rw-store
							fi
						'';
					};
				};

				virtualisation.docker.enable = true;

				fileSystems = {
					"/nix/.rw-store" = {
						fsType = "tmpfs";
						options = [ "size=16G" "mode=0755" ];
						neededForBoot = true;
					};

					"/var/lib/claude-rw" = {
						device = "/var/lib/cc-sandbox/claude-overlay.img";
						fsType = "ext4";
						options = [ "loop" ];
					};

					"/root/.claude".overlay = {
						lowerdir = [ "/var/lib/claude-lower" ];
						upperdir = "/var/lib/claude-rw/upper";
						workdir = "/var/lib/claude-rw/work";
					};
				};
			})
		];
	in {
		packages = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			runner = self.nixosConfigurations.${configName system}.config.microvm.declaredRunner;
		in rec {
			netfilter = pkgs.stdenv.mkDerivation {
				pname = "cc-sandbox-netfilter";
				version = "0.1.0";
				src = lib.cleanSourceWith {
					filter = name: type: !(
						lib.hasSuffix ".nix" (toString name)
						|| lib.hasSuffix ".lock" (toString name)
					);
					src = lib.cleanSource ./netfilter;
				};
				nativeBuildInputs = [ pkgs.zig ];
				dontConfigure = true;
				dontInstall = true;
				buildPhase = ''
					export HOME=$TMPDIR
					zig build --prefix $out -Doptimize=ReleaseSafe \
						--global-cache-dir $TMPDIR/.zig-global-cache
				'';
			};
			passt-cc = pkgs.passt.overrideAttrs (old: {
				# Allow rt_sigreturn so LD_PRELOAD signal handlers work
				# under passt's seccomp filter (needed for SIGUSR1 rule reload)
				makeFlags = (old.makeFlags or []) ++ [ "EXTRA_SYSCALLS=rt_sigreturn" ];
			});
			cc-sandbox = pkgs.writeShellApplication {
				name = "cc-sandbox";
				runtimeInputs = with pkgs; [ coreutils gnused gnugrep jq ] ++ [ passt-cc ];
				text = illustris-lib.replaceVarsInString {
					runtimeDir = runtimeDir;
					runner = "${runner}";
					netfilter = "${netfilter}/lib/libnetfilter.so";
				} null (builtins.readFile ./cc-sandbox.sh);
			};
			default = cc-sandbox;
		});

		checks = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
		in {
			netfilter-tests = pkgs.stdenv.mkDerivation {
				pname = "cc-sandbox-netfilter-tests";
				version = "0.1.0";
				src = lib.cleanSourceWith {
					filter = name: type: !(
						lib.hasSuffix ".nix" (toString name)
						|| lib.hasSuffix ".lock" (toString name)
					);
					src = lib.cleanSource ./netfilter;
				};
				nativeBuildInputs = [ pkgs.zig ];
				dontConfigure = true;
				dontInstall = true;
				buildPhase = ''
					export HOME=$TMPDIR
					zig build test --global-cache-dir $TMPDIR/.zig-global-cache \
						&& touch $out
				'';
			};
		} // lib.optionalAttrs (system == "x86_64-linux") {
			cc-sandbox-vm = pkgs.testers.runNixOSTest (import ./tests/cc-sandbox.nix {
				inherit self pkgs system;
			});
		});

		nixosConfigurations = lib.listToAttrs (map (system: {
			name = configName system;
			value = mkMicrovm system "cc-sandbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = ccSandboxModules system;
			};
		}) supportedSystems);
	};
}
