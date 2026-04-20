{
	description = "cc-sandbox MicroVM";

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
		nixpkgs-master.url = "github:nixos/nixpkgs?ref=master";
		microvm = {
			url = "github:microvm-nix/microvm.nix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
		nix-mcp.url = "github:illustris/nix-mcp";
		nixfs.url = "github:illustris/nixfs";
	};

	outputs = { self, nixpkgs, microvm, nix-mcp, ... }@inputs: let
		system = "x86_64-linux";
		pkgs = nixpkgs.legacyPackages.${system};

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

		mkMicrovm = name: {
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

		runner = self.nixosConfigurations.cc-sandbox.config.microvm.declaredRunner;
	in {
		packages.${system} = rec {
			cc-sandbox = pkgs.writeShellApplication {
				name = "cc-sandbox";
				runtimeInputs = with pkgs; [ coreutils gnused jq ];
				text = ''
					CONFIG_DIR="''${XDG_CONFIG_HOME:-$HOME/.config}/cc-sandbox"

					REAL_DATA="''${CC_SANDBOX_DATA:-$HOME/.local/share/cc-sandbox}"
					REAL_CLAUDE_CONFIG="''${CC_SANDBOX_CLAUDE_CONFIG:-$HOME/.claude}"
					REAL_CLAUDE_AUTH="''${CC_SANDBOX_CLAUDE_AUTH:-$HOME/.claude.json}"

					# -- First-time init: collect missing items, prompt once --------
					ITEMS=()
					if [ ! -f "$CONFIG_DIR/config.json" ]; then
						ITEMS+=("$CONFIG_DIR/config.json  (default settings)")
					fi
					if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
						ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, empty)")
					fi
					if [ ! -d "$REAL_DATA" ]; then
						ITEMS+=("$REAL_DATA/  (VM data)")
					fi
					if [ ! -d "$REAL_CLAUDE_CONFIG" ]; then
						ITEMS+=("$REAL_CLAUDE_CONFIG/  (Claude config)")
					fi
					if [ ! -f "$REAL_CLAUDE_AUTH" ]; then
						ITEMS+=("$REAL_CLAUDE_AUTH  (Claude auth)")
					fi

					if [ "''${#ITEMS[@]}" -gt 0 ]; then
						echo "The following paths will be created:"
						for item in "''${ITEMS[@]}"; do
							echo "  $item"
						done
						echo ""
						read -rp "Continue? [y/N] " confirm
						if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
							echo "Aborted."
							exit 1
						fi

						mkdir -p "$CONFIG_DIR" "$REAL_DATA" "$REAL_CLAUDE_CONFIG"

						if [ ! -f "$CONFIG_DIR/config.json" ]; then
							jq -n --tab '{
								vcpu: 16,
								mem: 32768,
								sshPort: 2222,
								httpPort: 8080,
								overlaySize: "128M",
								storeOverlaySize: "16G",
								bindAddr: "127.0.0.1"
							}' > "$CONFIG_DIR/config.json"
						fi
						if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
							touch "$CONFIG_DIR/authorized_keys"
						fi
						if [ ! -f "$REAL_CLAUDE_AUTH" ]; then
							echo '{}' > "$REAL_CLAUDE_AUTH"
							chmod 600 "$REAL_CLAUDE_AUTH"
						fi
					fi

					# -- Validate and read runtime config --------------------------
					if ! jq empty "$CONFIG_DIR/config.json" 2>/dev/null; then
						echo "Error: invalid JSON in $CONFIG_DIR/config.json"
						exit 1
					fi

					VCPU=$(jq -r '.vcpu // 16' "$CONFIG_DIR/config.json")
					MEM=$(jq -r '.mem // 32768' "$CONFIG_DIR/config.json")
					SSH_PORT=$(jq -r '.sshPort // 2222' "$CONFIG_DIR/config.json")
					HTTP_PORT=$(jq -r '.httpPort // 8080' "$CONFIG_DIR/config.json")
					OVERLAY_SIZE=$(jq -r '.overlaySize // "128M"' "$CONFIG_DIR/config.json")
					STORE_OVERLAY_SIZE=$(jq -r '.storeOverlaySize // "16G"' "$CONFIG_DIR/config.json")
					BIND_ADDR=$(jq -r '.bindAddr // "127.0.0.1"' "$CONFIG_DIR/config.json")

					# -- Write VM-side config into the data directory --------------
					mkdir -p "$REAL_DATA/.config"
					echo "$OVERLAY_SIZE" > "$REAL_DATA/.config/overlay-size"
					echo "$STORE_OVERLAY_SIZE" > "$REAL_DATA/.config/store-overlay-size"
					cp "$CONFIG_DIR/authorized_keys" "$REAL_DATA/.config/authorized_keys"

					# -- Set up runtime symlink directory for QEMU -----------------
					RUNTIME="${runtimeDir}"
					if [ -e "$RUNTIME" ]; then
						if [ -f "$RUNTIME/pid" ] && kill -0 "$(cat "$RUNTIME/pid")" 2>/dev/null; then
							echo "Another cc-sandbox instance is running (PID $(cat "$RUNTIME/pid"))."
							exit 1
						fi
						rm -rf "$RUNTIME"
					fi
					mkdir -p "$RUNTIME"
					echo "$$" > "$RUNTIME/pid"
					trap 'rm -rf "${runtimeDir}"' EXIT

					ln -sfn "$REAL_DATA" "$RUNTIME/data"
					ln -sfn "$REAL_CLAUDE_CONFIG" "$RUNTIME/claude-config"
					ln -sfn "$REAL_CLAUDE_AUTH" "$RUNTIME/claude-auth.json"

					# -- Patch the microvm runner with runtime QEMU settings -------
					sed -E \
						-e "s/( )-smp [0-9]+/\1-smp $VCPU/" \
						-e "s/( )-m [0-9]+/\1-m $MEM/" \
						-e "s/hostfwd=tcp:[^-]*-:22/hostfwd=tcp:$BIND_ADDR:$SSH_PORT-:22/g" \
						-e "s/hostfwd=tcp:[^-]*-:8080/hostfwd=tcp:$BIND_ADDR:$HTTP_PORT-:8080/g" \
						"${runner}/bin/microvm-run" > "$RUNTIME/run"
					chmod +x "$RUNTIME/run"

					exec "$RUNTIME/run"
				'';
			};
			default = cc-sandbox;
		};

		nixosConfigurations.cc-sandbox = mkMicrovm "cc-sandbox" {
			vcpu = 16;
			mem = 32768;
			extraModules = [
				inputs.nixfs.nixosModules.nixfs
				({ pkgs, lib, ... }: let
					claude-code-bin = (import inputs.nixpkgs-master {
						inherit system;
						config.allowUnfree = true;
					}).claude-code-bin;
				in {
					nixpkgs.config.allowUnfree = true;

					services.openssh.enable = true;

					# SSH keys are loaded at runtime from the data directory
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
						bpftrace
						claude-code-bin
						git
						curl
						jq
						vim
						ncdu
						nix-mcp.packages.${system}.default
						tmux
						(writeScriptBin "c" ''IS_SANDBOX=1 exec ${lib.getExe claude-code-bin} --dangerously-skip-permissions "$@"'')
						htop
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
		};
	};
}
