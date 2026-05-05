{
	description = "cogbox MicroVM";

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
		userExtensions.url = "path:./userExtensions";
	};

	outputs = { self, nixpkgs, microvm, nix-mcp, ... }@inputs: let
		lib = nixpkgs.lib;
		illustris-lib = import "${inputs.illustris-lib}/lib" { inherit lib; };
		supportedSystems = [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
		forAllSystems = f: lib.genAttrs supportedSystems f;

		archSuffix = system: builtins.head (lib.splitString "-" system);
		configName = system: "cogbox-${archSuffix system}";

		# Sentinel placeholder baked into the microvm runner's QEMU args
		# (9p share sources, fw_cfg file paths). At launch the wrapper
		# sed-rewrites this prefix to the resolved per-user XDG runtime
		# dir ($XDG_RUNTIME_DIR/cogbox), then populates it with
		# symlinks to the user's data/config locations. The literal
		# value here is irrelevant beyond being a unique, stable string
		# for the substitution to find.
		runtimeDir = "/tmp/cogbox";
		dataDir = "${runtimeDir}/data";

		# --- Harness configuration --------------------------------------
		# Single source of truth for how each coding-agent harness is
		# wired into the VM. Iterated below to emit systemPackages,
		# microvm.shares, qemu.extraArgs, systemd services, and
		# fileSystems. The cogbox.sh wrapper iterates the same shape
		# (re-declared in bash) to seed host state and create the runtime
		# symlinks the QEMU runner expects.
		#
		# Path kinds:
		#   overlay   - 9p RO lowerdir from host + persistent upperdir
		#               in the shared harness overlay image
		#   fw_cfg    - single host file copied into the guest at boot
		#               via QEMU's fw_cfg device
		#   ephemeral - sandbox-only; bind-mounted from the harness
		#               overlay image (no host source)
		mkHarnesses = system: pkgs: lib.filterAttrs (_: h: h.enable) {
			claude-code = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = (import inputs.nixpkgs-master {
					inherit system;
					config.allowUnfree = true;
				}).claude-code;
				launcher = {
					name = "c";
					flags = [ "--dangerously-skip-permissions" ];
					env = { IS_SANDBOX = "1"; };
				};
				paths = {
					config = {
						guest = "/root/.claude";
						kind = "overlay";
					};
					auth = {
						guest = "/root/.claude.json";
						kind = "fw_cfg";
						mode = "0600";
					};
				};
			};

			opencode = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
				package = pkgs.opencode;
				launcher = {
					name = "oc";
					# `--dangerously-skip-permissions` exists only on the
					# `run` subcommand (one-shot mode); the default TUI
					# command parses with yargs `.strict()` and would
					# reject it. `OPENCODE_PERMISSION` is the universal
					# bypass: opencode JSON.parses it and merges it into
					# `config.permission`. The string shorthand `"allow"`
					# normalizes to `{"*": "allow"}`, which `fromConfig`
					# expands to a single `{permission:"*", pattern:"*",
					# action:"allow"}` rule -- matching every tool/pattern
					# at evaluate time so opencode never raises a prompt.
					flags = [];
					env = {
						IS_SANDBOX = "1";
						OPENCODE_PERMISSION = ''"allow"'';
					};
				};
				paths = {
					config = {
						guest = "/root/.config/opencode";
						kind = "overlay";
					};
					# Includes auth.json, mcp-auth.json, log/, project/.
					# Single mount covers auth + state because opencode
					# keeps them together under XDG_DATA_HOME.
					data = {
						guest = "/root/.local/share/opencode";
						kind = "overlay";
					};
					cache = {
						guest = "/root/.cache/opencode";
						kind = "ephemeral";
					};
					state = {
						guest = "/root/.local/state/opencode";
						kind = "ephemeral";
					};
				};
			};
		};

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

		# `userExt` defaults to the no-op userExtensions input but can be
		# overridden by tests to inject a known module in the same list
		# position the runtime override-input would, so the resulting
		# microvm runner has a deterministic .drvPath that matches what
		# `nix run --override-input userExtensions ...` produces.
		cogboxModules = system: { userExt ? inputs.userExtensions.nixosModules.default }: let
			hasNixMcp = builtins.hasAttr system (nix-mcp.packages or {});
		in [
			inputs.nixfs.nixosModules.nixfs
			userExt
			({ pkgs, lib, utils, ... }: let
				harnesses = mkHarnesses system pkgs;

				# Flatten harnesses into a list of paths annotated with
				# their owning harness name and path key.
				allPaths = lib.concatLists (lib.mapAttrsToList (hname: h:
					lib.mapAttrsToList (pkey: p: p // { harness = hname; pathkey = pkey; }) h.paths
				) harnesses);
				pathsByKind = kind: lib.filter (p: p.kind == kind) allPaths;
				overlayPaths = pathsByKind "overlay";
				fwCfgPaths = pathsByKind "fw_cfg";
				ephemeralPaths = pathsByKind "ephemeral";

				# Naming conventions, used in both this flake and the
				# wrapper. Keep them in sync.
				sentinel = h: k: "${runtimeDir}/${h}-${k}";
				tag = h: k: "${h}-${k}";
				lowerMount = h: k: "/var/lib/harness-lower/${h}/${k}";
				upperDir = h: k: "/var/lib/harness-rw/${h}/${k}/upper";
				workDir = h: k: "/var/lib/harness-rw/${h}/${k}/work";
				ephemeralSrc = h: k: "/var/lib/harness-rw/${h}/${k}";

				mkLauncher = h: pkgs.writeScriptBin h.launcher.name (
					let
						envParts = lib.mapAttrsToList (k: v: "${k}=${lib.escapeShellArg v}") h.launcher.env;
						envStr = lib.concatStringsSep " " envParts;
						flagsStr = lib.concatStringsSep " " (map lib.escapeShellArg h.launcher.flags);
					in ''exec env ${envStr} ${lib.getExe h.package} ${flagsStr} "$@"''
				);

				# All harness mount units (overlay + ephemeral). Used to
				# wire harness-setup-dirs.service in front of every per-
				# path mount.
				harnessMountUnits = map (p: "${utils.escapeSystemdPath p.guest}.mount")
					(overlayPaths ++ ephemeralPaths);
			in {
				nixpkgs.config.allowUnfree = true;

				services.openssh.enable = true;

				environment.systemPackages = with pkgs; [
					git
					curl
					jq
					vim
					ncdu
					tmux
					htop
				]
				++ lib.concatMap (h: [ h.package (mkLauncher h) ]) (lib.attrValues harnesses)
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
					shares = map (p: {
						proto = "9p";
						tag = tag p.harness p.pathkey;
						source = sentinel p.harness p.pathkey;
						mountPoint = lowerMount p.harness p.pathkey;
						readOnly = true;
					}) overlayPaths;
					qemu.extraArgs = lib.concatMap (p: [
						"-fw_cfg"
						"name=opt/${tag p.harness p.pathkey},file=${sentinel p.harness p.pathkey}"
					]) fwCfgPaths;
				};

				# Per-fw_cfg copy services. Each one materializes a single
				# host file (auth token, etc.) into its guest path at boot.
				systemd.services = lib.listToAttrs (map (p:
					lib.nameValuePair "${p.harness}-${p.pathkey}" {
						description = "Copy ${p.harness}/${p.pathkey} from fw_cfg";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" ];
						serviceConfig = {
							Type = "oneshot";
							ExecStart = "/bin/sh -c 'cp /sys/firmware/qemu_fw_cfg/by_name/opt/${tag p.harness p.pathkey}/raw ${p.guest} && chmod ${p.mode} ${p.guest}'";
							RemainAfterExit = true;
						};
					}
				) fwCfgPaths) // {
					load-ssh-keys = {
						description = "Load SSH authorized keys from shared config";
						wantedBy = [ "multi-user.target" ];
						before = [ "sshd.service" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "load-ssh-keys" ''
								keyfile=/var/lib/cogbox/.config/authorized_keys
								if [ -f "$keyfile" ] && [ -s "$keyfile" ]; then
									mkdir -p /root/.ssh
									chmod 700 /root/.ssh
									cp "$keyfile" /root/.ssh/authorized_keys
									chmod 600 /root/.ssh/authorized_keys
								fi
							'';
						};
					};
					harness-overlay-img = {
						description = "Create ext4 image for harness overlay";
						wantedBy = [ "var-lib-harness\\x2drw.mount" ];
						before = [ "var-lib-harness\\x2drw.mount" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "harness-overlay-img" ''
								img=/var/lib/cogbox/harness-overlay.img
								old_img=/var/lib/cogbox/claude-overlay.img
								# Migration: pre-multi-harness installs had
								# the image named after the only harness.
								# The wrapper renames host-side at launch,
								# but cover the case where the guest is
								# booted by something else.
								if [ ! -f "$img" ] && [ -f "$old_img" ]; then
									mv "$old_img" "$img"
								fi
								if [ ! -f "$img" ]; then
									size="128M"
									sizefile=/var/lib/cogbox/.config/overlay-size
									if [ -f "$sizefile" ]; then
										size=$(cat "$sizefile")
									fi
									${pkgs.coreutils}/bin/truncate -s "$size" "$img"
									${pkgs.e2fsprogs}/bin/mkfs.ext4 -q "$img"
								fi
							'';
						};
					};

					harness-setup-dirs = {
						description = "Create per-harness subdirs in harness overlay";
						wantedBy = harnessMountUnits;
						before = harnessMountUnits;
						after = [ "var-lib-harness\\x2drw.mount" ];
						requires = [ "var-lib-harness\\x2drw.mount" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "harness-setup-dirs" ''
								base=/var/lib/harness-rw

								# Migration: pre-multi-harness images had
								# upper/ and work/ at the root (single
								# Claude overlay). Move into the new
								# claude-code/config/ subdir layout.
								if [ -d "$base/upper" ] && [ ! -d "$base/claude-code/config/upper" ]; then
									mkdir -p "$base/claude-code/config"
									mv "$base/upper" "$base/claude-code/config/upper"
									[ -d "$base/work" ] && mv "$base/work" "$base/claude-code/config/work"
								fi

								${lib.concatMapStringsSep "\n" (p: ''
									mkdir -p ${upperDir p.harness p.pathkey} ${workDir p.harness p.pathkey}
								'') overlayPaths}
								${lib.concatMapStringsSep "\n" (p: ''
									mkdir -p ${ephemeralSrc p.harness p.pathkey}
								'') ephemeralPaths}
							'';
						};
					};

					resize-store-overlay = {
						description = "Resize writable nix store overlay from config";
						wantedBy = [ "multi-user.target" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "resize-store-overlay" ''
								sizefile=/var/lib/cogbox/.config/store-overlay-size
								if [ -f "$sizefile" ]; then
									size=$(cat "$sizefile")
									${pkgs.util-linux}/bin/mount -o "remount,size=$size" /nix/.rw-store
								fi
							'';
						};
					};
				};

				virtualisation.docker.enable = true;

				fileSystems = {
					"/nix/.rw-store" = {
						fsType = "tmpfs";
						options = [ "size=16G" "mode=0755" ];
						neededForBoot = true;
					};

					"/var/lib/harness-rw" = {
						device = "/var/lib/cogbox/harness-overlay.img";
						fsType = "ext4";
						options = [ "loop" ];
					};
				} // lib.listToAttrs (
					(map (p: lib.nameValuePair p.guest {
						overlay = {
							lowerdir = [ (lowerMount p.harness p.pathkey) ];
							upperdir = upperDir p.harness p.pathkey;
							workdir = workDir p.harness p.pathkey;
						};
					}) overlayPaths)
					++ (map (p: lib.nameValuePair p.guest {
						device = ephemeralSrc p.harness p.pathkey;
						fsType = "none";
						options = [ "bind" ];
					}) ephemeralPaths)
				);
			})
		];
	in {
		packages = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			runner = self.nixosConfigurations.${configName system}.config.microvm.declaredRunner;
			mkCogbox = runner': pkgs.writeShellApplication {
				name = "cogbox";
				runtimeInputs = with pkgs; [ coreutils gnused gnugrep jq diffutils nix ] ++ [ self.packages.${system}.passt-cc ];
				text = illustris-lib.replaceVarsInString {
					runtimeDir = runtimeDir;
					runner = "${runner'}";
					netfilter = "${self.packages.${system}.cogbox-tools}/lib/libnetfilter.so";
					rules = "${self.packages.${system}.cogbox-tools}/bin/cogbox-rules";
					flakeSource = "${self}";
					nixpkgsSource = "${nixpkgs}";
				} null (builtins.readFile ./cogbox.sh);
			};
		in rec {
			cogbox-tools = pkgs.stdenv.mkDerivation {
				pname = "cogbox-tools";
				version = "0.1.0";
				src = lib.cleanSourceWith {
					filter = name: type: !(
						lib.hasSuffix ".nix" (toString name)
						|| lib.hasSuffix ".lock" (toString name)
					);
					src = lib.cleanSource ./zig;
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
			# Backwards-compatible alias
			netfilter = cogbox-tools;
			passt-cc = pkgs.passt.overrideAttrs (old: {
				# Allow rt_sigreturn so LD_PRELOAD signal handlers work
				# under passt's seccomp filter (needed for SIGUSR1 rule reload)
				makeFlags = (old.makeFlags or []) ++ [ "EXTRA_SYSCALLS=rt_sigreturn" ];
			});
			cogbox = mkCogbox runner;
			default = cogbox;
		} // lib.optionalAttrs (system == "x86_64-linux") {
			# Test fixture: a cogbox wrapper baked against the
			# pre-built test-hello runner. Used by tests/cogbox.nix
			# Phase E to make the offline NixOS test machine's
			# `nix run --override-input userExtensions ...` resolve as a
			# cache hit instead of building the transitive .drv graph
			# (which would fail with no network).
			cogbox-test-hello = mkCogbox
				self.nixosConfigurations.cogbox-x86_64-test-hello.config.microvm.declaredRunner;
		});

		checks = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
		in {
			zig-tests = pkgs.stdenv.mkDerivation {
				pname = "cogbox-zig-tests";
				version = "0.1.0";
				src = lib.cleanSourceWith {
					filter = name: type: !(
						lib.hasSuffix ".nix" (toString name)
						|| lib.hasSuffix ".lock" (toString name)
					);
					src = lib.cleanSource ./zig;
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
			cogbox-vm = pkgs.testers.runNixOSTest (import ./tests/cogbox.nix {
				inherit self pkgs system;
			});
		});

		nixosConfigurations = lib.listToAttrs (map (system: {
			name = configName system;
			value = mkMicrovm system "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules system {};
			};
		}) supportedSystems) // {
			# Test fixture used by tests/cogbox.nix Phase E. Pre-builds
			# a runner whose closure includes pkgs.hello, so the offline
			# NixOS test machine has the cached output of the
			# user-customised runner that Phase E reconstructs at runtime
			# via `nix run --override-input userExtensions ...`. The
			# `userExt` parameter inserts the hello-adding module in the
			# same list position userExtensions normally occupies, so the
			# resulting .drvPath is byte-identical to the runtime path.
			cogbox-x86_64-test-hello = mkMicrovm "x86_64-linux" "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules "x86_64-linux" {
					userExt = { pkgs, ... }: {
						environment.systemPackages = [ pkgs.hello ];
						system.extraDependencies = [ pkgs.hello ];
					};
				};
			};
		};
	};
}
