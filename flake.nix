{
	description = "cogbox MicroVM";

	# A flake's nixConfig is only honored when it is the *top-level*
	# flake; an input's nixConfig is deliberately never propagated to the
	# consumer. So even though llm-agents.nix declares cache.numtide.com,
	# building cogbox would ignore it and rebuild every harness (codex,
	# etc.) from source. nixConfig also cannot reference `inputs` (it is a
	# static attr, evaluated before outputs), so these values are mirrored
	# by hand from numtide/llm-agents.nix's own flake.nix nixConfig.
	# Re-sync if upstream rotates the cache URL or signing key.
	nixConfig = {
		extra-substituters = [ "https://cache.numtide.com" ];
		extra-trusted-public-keys = [ "niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g=" ];
	};

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
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
		# Intentionally not setting inputs.nixpkgs.follows: llm-agents.nix
		# publishes its builds to cache.numtide.com against its own pinned
		# nixpkgs, and overriding it would force local rebuilds of every
		# harness against our nixpkgs revision instead of cache hits.
		llm-agents.url = "github:numtide/llm-agents.nix";
		userExtensions.url = "path:./userExtensions";
	};

	outputs = { self, nixpkgs, microvm, nix-mcp, ... }@inputs: let
		lib = nixpkgs.lib;
		illustris-lib = import "${inputs.illustris-lib}/lib" { inherit lib; };
		supportedSystems = [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
		forAllSystems = f: lib.genAttrs supportedSystems f;
		mkHermesHomeHelper = pkgs: pkgs.writeShellApplication {
			name = "cogbox-hermes-home";
			runtimeInputs = [ pkgs.coreutils pkgs.findutils ];
			text = builtins.readFile ./cogbox-hermes-home.sh;
		};

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
		#
		# Codex is OPT-IN. Its Rust toolchain build is slow and frequently a
		# cache miss against our nixpkgs, so it is disabled by default to keep
		# cogbox builds fast. Flip this to `true` to build it in. Everything
		# downstream is derived from the resulting harness set -- the VM's
		# packages/mounts/services AND the launcher's HARNESSES list (baked in
		# via the @harnesses@ sentinel) -- so this single switch covers both.
		enableCodex = false;
		# pi is OPT-IN. The per-instance full system toplevel is built inside a
		# FAIL-CLOSED worker pod with no registry.npmjs.org egress. pi is the only
		# harness cogbox patches via `.overrideAttrs` (the Bun->Node entrypoint fix
		# below), which changes pi's derivation hash so numtide's published pi is a
		# cache MISS -- forcing a source build that fetches the pi npm tarball from
		# npmjs, which the worker cannot reach, hanging/timing out the toplevel build.
		# Disabling by default keeps pi out of the
		# per-instance toplevel so the worker never builds it. Flip to `true` to build
		# it in. (Hermes stays enabled: used unmodified, so it's a cache hit and never
		# builds in the worker.)
		enablePi = false;
		mkHarnesses = system: pkgs: let
			llmPkgs = inputs.llm-agents.inputs.nixpkgs.legacyPackages.${system};
		in lib.filterAttrs (_: h: h.enable) {
			claude-code = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.claude-code;
				launcher = {
					name = "c";
					flags = [ "--dangerously-skip-permissions" ];
					env = { IS_SANDBOX = "1"; };
					# No injected auth-token env var: the guest ALWAYS gets a present,
					# redacted-scoped .credentials.json (stage_overlay_source stages a
					# placeholder identity even on a staging failure), so claude-code
					# reads the file -- the host proxy injects the real token over the
					# stub, /remote-control's local-cred gate is satisfied, and an
					# in-guest /login can write its OWN token over the placeholder
					# (which then persists per-instance and stops host inheritance).
					# An auth-token env var would shadow the file, breaking all three.
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
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.opencode;
				launcher = {
					name = "oc";
					# `--dangerously-skip-permissions` exists only on the
					# `run` subcommand (one-shot mode); the default TUI
					# command parses with yargs `.strict()` and would
					# reject it. `OPENCODE_PERMISSION` is the universal
					# bypass: opencode JSON.parses it and merges it into
					# `config.permission`. opencode 1.16.2 requires the
					# object form keyed by category; a bare `"allow"` string
					# is rejected -- the schema indexes it char by char
					# (got "a" from "allow"[0]). Set every category to `allow`
					# so opencode never prompts (`bash` also takes a {pattern:
					# action} map; plain `"allow"` covers all patterns).
					flags = [];
					env = {
						IS_SANDBOX = "1";
						OPENCODE_PERMISSION = ''{"edit":"allow","bash":"allow","webfetch":"allow","doom_loop":"allow","external_directory":"allow"}'';
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

			codex = {
				# Opt-in (slow Rust build): gated on `enableCodex` above.
				enable = enableCodex && builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.codex;
				launcher = {
					name = "cx";
					# `--dangerously-bypass-approvals-and-sandbox` is codex's
					# documented escape hatch: skips all confirmation prompts
					# and runs commands without codex's own sandbox. Cogbox
					# already provides the outer microvm sandbox, so this is
					# the equivalent of claude-code's `--dangerously-skip-permissions`.
					flags = [ "--dangerously-bypass-approvals-and-sandbox" ];
					env = { IS_SANDBOX = "1"; };
				};
				paths = {
					# Codex stores config, auth, sessions, helper binaries
					# (tmp/), and rollouts together under $CODEX_HOME
					# (default ~/.codex). A single overlay covers everything,
					# matching opencode's auth-inside-data pattern.
					home = {
						guest = "/root/.codex";
						kind = "overlay";
					};
				};
			};

			hermes-agent = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.hermes-agent;
				launcher = {
					name = "h";
					# `HERMES_YOLO_MODE=1` bypasses hermes's dangerous-command
					# approval prompts (equivalent to `--yolo`, but the env var
					# covers every subcommand -- chat, gateway, cron -- not just
					# the ones that grow the flag). Hermes's hardline blocklist
					# (rm -rf /, fork bombs, ...) stays active regardless; that
					# is a code-level constant, not a prompt.
					flags = [];
					env = { HERMES_YOLO_MODE = "1"; };
				};
				paths = {
					# Hermes keeps everything under $HERMES_HOME (default
					# ~/.hermes): config.yaml, the .env credential file
					# (provider API keys), skills, and session state. A single
					# overlay covers it all, matching codex's pattern.
					home = {
						guest = "/root/.hermes";
						kind = "overlay";
					};
				};
			};

			pi = {
				# Opt-in (fail-closed worker can't fetch the overridden pi from npmjs): gated on `enablePi` above.
				enable = enablePi && builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.pi.overrideAttrs (_: {
					# Retain npm's Node entrypoint for runtime compatibility.
					preInstall = "";
					postInstall = ''
						wrapProgram $out/bin/pi \
							--prefix PATH : ${llmPkgs.lib.makeBinPath [ llmPkgs.fd llmPkgs.ripgrep ]} \
							--set PI_SKIP_VERSION_CHECK 1 \
							--set PI_TELEMETRY 0
					'';
				});
				launcher = {
					name = "p";
					# pi has no permission system at all (documented upstream:
					# no built-in restriction of filesystem/process/network
					# access), so full-auto needs no flag or env -- the outer
					# microvm sandbox is the only containment, same as the
					# other harnesses.
					flags = [];
					env = {};
				};
				paths = {
					# pi keeps config, auth (auth.json: per-provider API keys
					# and OAuth tokens), models.json, settings.json, and
					# sessions/ together under ~/.pi/agent. Mount the whole
					# ~/.pi so sibling pi-mono tools' state is covered too.
					home = {
						guest = "/root/.pi";
						kind = "overlay";
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
					# `@cogbox-instance@` is a sentinel rewritten by
					# cogbox-launch.sh to the active instance name, so
					# systemd applies `cogbox-<instance>` as the hostname
					# during early boot. Anchored on `systemd.hostname=`
					# rather than the raw token to avoid collisions if
					# the placeholder ever appears verbatim elsewhere.
					# `nokaslr` is VM-only: it lives here in mkMicrovm (the QEMU
					# guest builder), never in the container's mkContainer, so the
					# container toplevel closure stays byte-identical. The guest
					# kernel otherwise hangs at early-boot KASLR relocation on an
					# RDRAND entropy draw that stalls under nested KVM (when the
					# host nodes are themselves VMs); disabling KASLR skips that draw.
					boot.kernelParams = [ "systemd.hostname=cogbox-@cogbox-instance@" "nokaslr" ];
					users.users.root.password = "";
					services.getty.autologinUser = "root";
					# Land interactive login shells in the persisted data
					# dir so the autologin session starts where the user's
					# state lives, rather than in root's home.
					# Land interactive login shells in the standardized workdir
					# ~/work (= /root/work, a base-created symlink into the persisted
					# share). mkForce so no plugin can append a competing `cd` -- the
					# cogbox.* contract has no loginShellInit surface. Falls back to
					# /root (NOT the data dir, which holds cogbox_ed25519 + instances/)
					# if the brain oneshot has not run yet.
					programs.bash.loginShellInit = lib.mkForce ''
						cd /root/work 2>/dev/null || cd /root
						# Prepend the plugin tools (cogbox.packages) the brain materialized.
						# Redundant on the VM (they are in systemPackages already) but keeps
						# parity with the container, where this is the only PATH surface.
						[ -d /root/work/.cogbox/brain/bin ] && export PATH="/root/work/.cogbox/brain/bin:$PATH"
					'';
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

		# Container-native backend: boot the
		# SAME guest userland as an unprivileged OCI container -- no QEMU, passt,
		# 9p, or fw_cfg. Reuses cogboxModules with target = "container" (the
		# VM-only plumbing is gated off there). The result's
		# config.system.build.toplevel is streamed into the agent-image below;
		# its /init is systemd PID1, which runs the reused brain/trust/l7-trust
		# oneshots to multi-user.target.
		mkContainer = system: name: { extraModules ? [] }: nixpkgs.lib.nixosSystem {
			inherit system;
			modules = [
				({ pkgs, lib, ... }: {
					# microvm.nixosModules.microvm is intentionally NOT imported for
					# the container. The shared guest module still carries a
					# `microvm = lib.mkIf isVm {...}` definition, so declare an inert,
					# invisible sink option to give it a home (isVm is false here, so
					# the definition is dropped and this stays {}).
					options.microvm = lib.mkOption {
						type = lib.types.attrs;
						default = {};
						visible = false;
						description = "Inert sink for the container target (no microvm).";
					};
					config = {
						boot.isContainer = true;
						system.stateVersion = "25.11";
						# No empty (or any) root password on the container: console
						# access is `kubectl exec` (a fresh process, no auth), and the
						# certificate-authenticated sshd must never fall through to a
						# password. Lock the account (`!`) instead of the VM's empty
						# password. mkForce guards against a plugin's full NixOS module.
						users.users.root.hashedPassword = lib.mkForce "!";
						# Land login + non-login shells in ~/work, same as the VM
						# (mkForce: no plugin appends a competing cd). Falls back to
						# /root (NOT COGBOX_DATA, which holds cogbox_ed25519 +
						# instances/) before the brain oneshot has run.
						programs.bash.loginShellInit = lib.mkForce ''
							cd /root/work 2>/dev/null || cd /root
							# Prepend the plugin tools (cogbox.packages) the brain
							# materialized into $out/bin. This is the container's ONLY PATH
							# surface for plugin tools (the base image is plugin-less), so it
							# is what makes `example-plugin-cli` et al. resolve in the
							# interactive terminal (tmux spawns a login shell).
							[ -d /root/work/.cogbox/brain/bin ] && export PATH="/root/work/.cogbox/brain/bin:$PATH"
						'';
						nix = {
							nixPath = [ "nixpkgs=${pkgs.path}" ];
							# NixOS owns /etc/nix/nix.conf, so express the cogbox-pod-image
							# nix.conf (single-user builds, no sandbox, public caches) as
							# options rather than a baked file.
							settings = {
								experimental-features = [ "nix-command" "flakes" ];
								build-users-group = "";
								sandbox = false;
								# CoW /nix (cogworx's CoW store mode) mounts a
								# node-shared READ-ONLY lower under a thin per-instance
								# overlay upper. Store auto-optimisation hardlinks identical
								# files together, which across the RO lower boundary either
								# EROFSes or forces needless copy-ups that defeat the CoW
								# savings. It buys nothing here anyway (the image store is
								# already optimised at build). mkForce so a plugin's full
								# NixOS module cannot re-enable it and break a cow instance.
								auto-optimise-store = lib.mkForce false;
								substituters = [ "https://cache.nixos.org" "https://cache.numtide.com" ];
								trusted-public-keys = [
									"cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
									"niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
								];
							};
						};
					};
				})
			] ++ extraModules;
		};

		# GCE backend host: the cogbox HOST half as a full NixOS system that
		# boots on Google Compute Engine under nested virtualization, running
		# the same microVM guest it runs locally and in a k8s pod. Unlike
		# mkMicrovm/mkContainer this is not another shape of the GUEST -- it is
		# the machine the guest runs inside, so it imports nixpkgs' GCE image
		# format and then spends most of ./gce/cogbox-host.nix undoing that
		# profile's metadata-driven defaults.
		#
		# x86_64 only, and the nixosConfigurations entry below is guarded to
		# match: GCE nested virtualization is Intel-series only (S1).
		#
		# `self` and `inputs` reach the modules through specialArgs because the
		# host module needs BOTH the built cogbox package and the flake INPUT
		# SOURCE TREES -- the second is what keeps the launcher's re-exec
		# evaluable with no egress (see system.extraDependencies there).
		mkGceHost = system: { extraModules ? [ ] }: nixpkgs.lib.nixosSystem {
			inherit system;
			specialArgs = { inherit self inputs system; };
			modules = [
				"${nixpkgs}/nixos/modules/virtualisation/google-compute-image.nix"
				./gce/cogbox-host.nix
			] ++ extraModules;
		};

		# `userExt` defaults to the no-op userExtensions input but can be
		# overridden by tests to inject a known module in the same list
		# position the runtime override-input would, so the resulting
		# microvm runner has a deterministic .drvPath that matches what
		# `nix run --override-input userExtensions ...` produces.
		cogboxModules = system: { userExt ? inputs.userExtensions.nixosModules.default, target ? "vm" }: let
			hasNixMcp = builtins.hasAttr system (nix-mcp.packages or {});
		in [
			# Declare the cogbox.* plugin-contribution option tree (the "brain"
			# contract). Every plugin module fills in its slice; the base module
			# below reads the merged config.cogbox and materializes it into each
			# enabled harness's native tree under ~/work. Host-side hot-reloadable
			# policy (networkRules/l7Rules/inject) is NOT here -- it lives in the
			# cogboxPlugins.<name> flake output, read cheaply at `plugin add`.
			({ lib, ... }: {
				options.cogbox = {
					# Convention root(s): each scanned (readDir, pure eval) for
					# skills/, agents/, commands/, rules/. A bare path coerces to a
					# one-element list so multiple plugins' roots concatenate.
					contents = lib.mkOption {
						type = lib.types.coercedTo lib.types.path (p: [ p ]) (lib.types.listOf lib.types.path);
						default = [];
						description = "Convention root(s) scanned for skills/, agents/, commands/, rules/.";
					};
					# Explicit units compose on top of discovery and override a
					# discovered name. Each value is a path: a skill is a dir
					# (containing SKILL.md), an agent/command/rule is a .md file.
					skills   = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit skill dirs (each containing SKILL.md), keyed by name."; };
					agents   = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit agent .md files, keyed by name."; };
					commands = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit command .md files, keyed by name."; };
					rules    = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit rule .md files (paths: frontmatter; empty => always-on), keyed by name."; };
					# Neutral MCP spec, materialized per-harness. serverName ->
					# { command/args/env } (stdio) or { url/headers } (remote).
					mcp      = lib.mkOption { type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything); default = {}; description = "Neutral MCP servers: name -> { command/args/env } | { url/headers }."; };
					# Lifecycle hooks: event -> command.
					hooks    = lib.mkOption { type = lib.types.attrsOf lib.types.str; default = {}; description = "Lifecycle hooks: event -> command."; };
					# Plugin-scoped env, re-emitted into the harness launchers only
					# (never a hard global environment.variables set).
					env      = lib.mkOption { type = lib.types.attrsOf lib.types.str; default = {}; description = "Plugin-scoped env, merged into the harness launcher env."; };
					# Plugin-contributed CLI tools that must be on the sandbox PATH.
					# The base folds these into BOTH environment.systemPackages (so the
					# VM bakes them into /run/current-system/sw/bin via the per-instance
					# runner rebuild) AND a $out/bin buildEnv inside cogbox-brain, which
					# the container backend prepends to the guest PATH -- its base image
					# is plugin-less, so systemPackages there never carry a plugin's
					# tools. Use this instead of environment.systemPackages so a plugin's
					# tools reach BOTH backends. (listOf package: plugins concatenate.)
					packages = lib.mkOption { type = lib.types.listOf lib.types.package; default = []; description = "Plugin-contributed packages placed on the sandbox PATH (systemPackages on the VM; brain/bin on the container)."; };
					# Per-harness settings -- NOT harness-agnostic (model strings
					# differ). ALLOWLIST per harness: model, reasoningEffort. Never
					# permissions/auth/providers. Keyed by harness name.
					settings = lib.mkOption {
						type = lib.types.attrsOf (lib.types.submodule {
							options = {
								model           = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
								reasoningEffort = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
							};
						});
						default = {};
						description = "Per-harness settings (allowlist: model, reasoningEffort). Keyed by claude-code/opencode/codex.";
					};
				};
			})
			userExt
			({ config, pkgs, lib, utils, ... }: let
				harnesses = mkHarnesses system pkgs;
				hermesHomeHelper = mkHermesHomeHelper pkgs;
				cfg = config.cogbox;

				# Build target: "vm" (the QEMU microvm, default) or "container"
				# (the unprivileged OCI agent image). The same guest module tree -- packages, harness
				# launchers, brain/trust/l7-trust oneshots -- serves both; the
				# VM-only plumbing below (microvm runner, 9p shares, fw_cfg
				# copies, harness overlay/loop filesystems, docker, sshd) is
				# gated to "vm" so the container drops it.
				isVm = target == "vm";
				isContainer = target == "container";
				# Container backend: the state volume mounts here, mirroring the
				# cogworx k8s pod env (XDG_CONFIG_HOME/COGBOX_DATA).
				stateRoot = "/var/lib/cogbox-state";
				cogboxData = "${stateRoot}/data/cogbox";
				# The VM's guest oneshots order after the 9p data mount; the
				# container has no such mount, so they order after the state-prep
				# oneshot that symlinks /var/lib/cogbox into the mounted state
				# (so ~/work resolves identically to the VM).
				stateUnit = if isVm then "var-lib-cogbox.mount" else "cogbox-container-state.service";
				# L7 trust CA source: fw_cfg in the VM, a mounted file in the
				# container (the enforcer publishes it; absent -> the unit yields the system
				# bundle, which is the no-enforcement default).
				l7CaSource = if isVm
					then "/sys/firmware/qemu_fw_cfg/by_name/opt/system-l7ca/raw"
					else "/var/run/cogbox-ca/ca.crt"; # enforcer publishes the CA cert here (agent ro mount)

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

				# CA bundle the L7 terminate tier injects. cogbox-l7-trust.service
				# assembles it at boot from the system trust store plus the
				# per-instance MITM CA (if terminate is active); when terminate is
				# off it is just the system bundle, so pointing tools at it
				# unconditionally is safe.
				l7CaBundle = "/run/cogbox/ca-bundle.crt";
				l7CaEnv = {
					SSL_CERT_FILE = l7CaBundle;
					NIX_SSL_CERT_FILE = l7CaBundle;
					CURL_CA_BUNDLE = l7CaBundle;
					GIT_SSL_CAINFO = l7CaBundle;
					REQUESTS_CA_BUNDLE = l7CaBundle;
					NODE_EXTRA_CA_CERTS = l7CaBundle;
				};

				mkLauncher = h: pkgs.writeScriptBin h.launcher.name (
					let
						# opencode reads its merged plugin config from OPENCODE_CONFIG
						# (deep-merged UNDER any user ./opencode.json), not the project
						# root, so a plugin's mcp/instructions/settings never clobber
						# the user's file. cogbox-set, so plugin env can't shadow it.
						ocConfig = lib.optionalAttrs (h.launcher.name == "oc") {
							OPENCODE_CONFIG = "/root/work/.cogbox/brain/opencode.json";
						};
						# Layer order: CA env first (a harness may override it), then
						# plugin-scoped cogbox.env, then the cogbox OPENCODE_CONFIG, then
						# the harness's own launcher env (wins). Plugin env is launcher-
						# scoped on purpose -- never a hard global environment.variables.
						envParts = lib.mapAttrsToList (k: v: "${k}=${lib.escapeShellArg v}")
							(l7CaEnv // cfg.env // ocConfig // h.launcher.env);
						envStr = lib.concatStringsSep " " envParts;
						flagsStr = lib.concatStringsSep " " (map lib.escapeShellArg h.launcher.flags);
					# Land non-login `cogbox ssh -- c/oc/cx` in the standardized
					# workdir too (loginShellInit covers the interactive login path).
					# Prepend the brain's plugin-tool bin to PATH so the harness AND its
					# tool subprocesses (e.g. claude-code's Bash) resolve cogbox.packages
					# tools -- this is what lets the AGENT invoke them, not just a human at
					# the terminal. Harness itself is found via the absolute getExe, so
					# PATH order never affects launching it. Bash expands $PATH at runtime
					# (literal in the '' string); redundant-but-harmless on the VM.
					in "#!${pkgs.runtimeShell}\n"
						+ "cd /root/work 2>/dev/null || true\n"
						+ ''exec env PATH="/root/work/.cogbox/brain/bin:$PATH" ${envStr} ${lib.getExe h.package} ${flagsStr} "$@"''
						+ "\n"
				);

				# All harness mount units (overlay + ephemeral). Used to
				# wire harness-setup-dirs.service in front of every per-
				# path mount.
				harnessMountUnits = map (p: "${utils.escapeSystemdPath p.guest}.mount")
					(overlayPaths ++ ephemeralPaths);

				# ===== Plugin brain: materialize config.cogbox into per-harness =====
				# native trees under ~/work. Pure eval (readDir/readFile over the
				# in-closure plugin sources); built once into the cogbox-brain
				# derivation and symlinked in by the cogbox-brain oneshot. See
				# docs/plugins.md (the cogbox.* contract).

				# --- readDir discovery (skill = dir with SKILL.md; agent/command/
				#     rule = <name>.md file) over each cogbox.contents root ---
				readDirSafe = dir: if builtins.pathExists dir then builtins.readDir dir else {};
				discoverSkills = root: let
					dir = root + "/skills";
				in lib.mapAttrs (n: _: dir + "/${n}")
					(lib.filterAttrs (n: t: t == "directory" && builtins.pathExists (dir + "/${n}/SKILL.md"))
						(readDirSafe dir));
				discoverMd = sub: root: let
					dir = root + "/${sub}";
				in lib.mapAttrs' (n: _: lib.nameValuePair (lib.removeSuffix ".md" n) (dir + "/${n}"))
					(lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".md" n && n != "README.md")
						(readDirSafe dir));

				mergeRoots = perRoot: lib.foldl' (a: b: a // b) {} perRoot;
				dupNames = perRoot: let
					names = lib.concatMap lib.attrNames perRoot;
					counts = lib.foldl' (acc: n: acc // { ${n} = (acc.${n} or 0) + 1; }) {} names;
				in lib.attrNames (lib.filterAttrs (_: c: c > 1) counts);

				roots = cfg.contents;
				perRootSkills   = map discoverSkills roots;
				perRootAgents   = map (discoverMd "agents") roots;
				perRootCommands = map (discoverMd "commands") roots;
				perRootRules    = map (discoverMd "rules") roots;

				# Explicit cogbox.{skills,...} compose on top of (and override) a
				# discovered unit of the same name -- explicit is the more
				# intentional declaration.
				skills   = mergeRoots perRootSkills   // cfg.skills;
				agents   = mergeRoots perRootAgents   // cfg.agents;
				commands = mergeRoots perRootCommands // cfg.commands;
				rules    = mergeRoots perRootRules    // cfg.rules;

				# Discovered-name collisions ACROSS contents roots (the base owns the
				# readDir merge, so it must catch these; explicit-name collisions are
				# caught for free by the module system's attrsOf merge).
				discoveredCollisions =
					(map (n: "skill '${n}'")   (dupNames perRootSkills))
					++ (map (n: "agent '${n}'")   (dupNames perRootAgents))
					++ (map (n: "command '${n}'") (dupNames perRootCommands))
					++ (map (n: "rule '${n}'")    (dupNames perRootRules));

				# --- minimal YAML-frontmatter reader (for the index + codex). Pure
				#     readFile over store paths; only flat `key: value` lines. ---
				trimWs = s: let m = builtins.match "[[:space:]]*(.*[^[:space:]]|)[[:space:]]*" s; in if m == null then s else builtins.head m;
				stripQuotes = s: let
					unq = q: x: if lib.hasPrefix q x && lib.hasSuffix q x && builtins.stringLength x >= 2
						then builtins.substring 1 (builtins.stringLength x - 2) x else x;
				in unq "'" (unq "\"" s);
				fmLinesOf = file: let
					content = if builtins.pathExists file then builtins.readFile file else "";
					lines = lib.splitString "\n" content;
					hasFm = lines != [] && lib.head lines == "---";
					afterFirst = if hasFm then lib.tail lines else [];
					closes = lib.filter (x: x.v == "---") (lib.imap0 (i: l: { i = i; v = l; }) afterFirst);
				in if !hasFm || closes == [] then [] else lib.take (lib.head closes).i afterFirst;
				fmOf = file: lib.listToAttrs (lib.filter (x: x != null) (map (l: let
					parts = lib.splitString ":" l;
				in if lib.length parts < 2 || lib.hasPrefix "#" (trimWs l) then null
					else lib.nameValuePair (trimWs (lib.head parts))
						(stripQuotes (trimWs (lib.concatStringsSep ":" (lib.tail parts))))) (fmLinesOf file)));
				# Collapse to a single line, neutralize the most obvious override
				# patterns, and length-cap a plugin-authored description before it
				# reaches the always-on index (defense-in-depth; see plan section 8).
				sanitize = s: let
					oneLine = lib.concatStringsSep " " (lib.splitString "\n" (lib.concatStringsSep " " (lib.splitString "\t" s)));
					neutralized = builtins.replaceStrings
						[ "ignore previous" "ignore all previous" "disregard previous" "system prompt" ]
						[ "(redacted)" "(redacted)" "(redacted)" "(redacted)" ]
						oneLine;
					capped = if builtins.stringLength neutralized > 200 then (builtins.substring 0 197 neutralized) + "..." else neutralized;
				in capped;

				# MCP secret-rejection: a neutral mcp server may name only
				# command/args/env/url/headers. A plugin can never inline a
				# token/cred_file/refresh/secret -- MCP auth goes through host-side
				# inject/sidecar (the same stance as the inject spec validator).
				mcpAllowedKeys = [ "command" "args" "env" "url" "headers" ];
				mcpViolations = lib.concatLists (lib.mapAttrsToList (srv: m:
					map (k: "${srv}.${k}") (lib.filter (k: !(lib.elem k mcpAllowedKeys)) (lib.attrNames m))) cfg.mcp);

				# --- per-harness config files (pkgs.formats; no hand-rolled JSON/TOML) ---
				jsonFmt = pkgs.formats.json {};
				tomlFmt = pkgs.formats.toml {};
				opencodeMcp = lib.mapAttrs (n: m:
					(if m ? command
						then { type = "local"; command = [ m.command ] ++ (m.args or []); enabled = true; }
							// lib.optionalAttrs (m ? env) { environment = m.env; }
						else { type = "remote"; url = m.url; enabled = true; }
							// lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				claudeMcp = lib.mapAttrs (n: m:
					(if m ? command
						then { command = m.command; args = m.args or []; } // lib.optionalAttrs (m ? env) { env = m.env; }
						else { type = "http"; url = m.url; } // lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				codexMcp = lib.mapAttrs (n: m:
					(if m ? command
						then { command = m.command; args = m.args or []; } // lib.optionalAttrs (m ? env) { env = m.env; }
						else { url = m.url; } // lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				settingsModel = h: let s = cfg.settings.${h} or null; in
					lib.optionalAttrs (s != null && s.model != null) { model = s.model; };
				claudeHooks = lib.mapAttrs (_: cmd: [ { hooks = [ { type = "command"; command = cmd; } ]; } ]) cfg.hooks;

				opencodeConfigAttrs = {
					"$schema" = "https://opencode.ai/config.json";
					instructions = [ ".cogbox/brain/rules/*.md" ];
				} // lib.optionalAttrs (cfg.mcp != {}) { mcp = opencodeMcp; }
					// settingsModel "opencode";
				opencodeConfig = jsonFmt.generate "opencode.json" opencodeConfigAttrs;

				claudeSettingsAttrs = settingsModel "claude-code"
					// lib.optionalAttrs (cfg.hooks != {}) { hooks = claudeHooks; };
				claudeSettings = jsonFmt.generate "settings.json" claudeSettingsAttrs;
				claudeMcpJson = jsonFmt.generate "mcp.json" { mcpServers = claudeMcp; };

				codexConfigAttrs = lib.optionalAttrs (cfg.mcp != {}) { mcp_servers = codexMcp; }
					// settingsModel "codex";
				codexConfig = tomlFmt.generate "config.toml" codexConfigAttrs;

				# --- the cogbox-authored capability index (the only always-on text) ---
				indexRows = lib.mapAttrsToList (n: p:
					"| `${n}` | ${sanitize ((fmOf (p + "/SKILL.md")).description or "")} |") skills;
				# Built as an explicit line list (NOT a '' here-string): a SKILL.md
				# whose `---` frontmatter is not at column 0 is not recognized by the
				# harness, and '' dedent leaves stray leading tabs.
				indexSkill = pkgs.writeTextDir "SKILL.md" (lib.concatStringsSep "\n" ([
					"---"
					"name: cogbox-plugins"
					"description: Index of capabilities installed in this sandbox; consult before answering domain questions."
					"---"
					""
					"# Installed capabilities"
					""
					"Plugin-provided skills available in this sandbox. Load a skill by relevance before answering domain questions in its area."
					""
					"| skill | description |"
					"|---|---|"
				] ++ indexRows) + "\n");

				# --- the materialized brain derivation (RO store leaves) ---
				linkInto = dir: ext: attrs: lib.concatStringsSep "\n"
					(lib.mapAttrsToList (n: p: ''ln -s ${p} "${dir}/${n}${ext}"'') attrs);
				# Plugin-contributed tools, merged into one bin/ tree. Fixed name so the
				# out-path is a pure function of cfg.packages -- the container prebuild
				# and boot rebuild must produce a byte-identical cogbox-brain out-path
				# (the boot substitutes it offline from the per-instance plugin-cache).
				# ignoreCollisions: a plugin listing tools whose closures share a bin
				# name must not FAIL the brain build (which would drop ALL its tools);
				# first-wins matches how environment.systemPackages already tolerates the
				# same set on the VM. Only /bin is linked (tools, not docs/man/lib).
				pluginBin = pkgs.buildEnv { name = "cogbox-plugin-bin"; paths = cfg.packages; pathsToLink = [ "/bin" ]; ignoreCollisions = true; };
				cogbox-brain = pkgs.runCommandLocal "cogbox-brain" {} (''
					set -e
					mkdir -p $out/rules
					${linkInto "$out/rules" ".md" rules}
				'' + lib.optionalString (harnesses ? "claude-code") ''
					mkdir -p $out/claude/skills $out/claude/agents $out/claude/commands
					${linkInto "$out/claude/skills" "" skills}
					ln -s ${indexSkill} $out/claude/skills/cogbox-plugins
					${linkInto "$out/claude/agents" ".md" agents}
					${linkInto "$out/claude/commands" ".md" commands}
					${lib.optionalString (claudeSettingsAttrs != {}) "cp ${claudeSettings} $out/claude/settings.json"}
					${lib.optionalString (cfg.mcp != {}) "cp ${claudeMcpJson} $out/claude/.mcp.json"}
				'' + lib.optionalString (harnesses ? "opencode") ''
					mkdir -p $out/opencode/skills $out/opencode/agents $out/opencode/commands
					${linkInto "$out/opencode/skills" "" skills}
					ln -s ${indexSkill} $out/opencode/skills/cogbox-plugins
					${linkInto "$out/opencode/agents" ".md" agents}
					${linkInto "$out/opencode/commands" ".md" commands}
					cp ${opencodeConfig} $out/opencode.json
				'' + lib.optionalString (harnesses ? "codex" || harnesses ? "pi") ''
					# The agentskills.io project layout, read natively by BOTH codex
					# (~/.agents/skills) and pi (.agents/skills in cwd/ancestors) --
					# one tree serves whichever of the two is enabled.
					mkdir -p $out/agents/skills
					${linkInto "$out/agents/skills" "" skills}
					ln -s ${indexSkill} $out/agents/skills/cogbox-plugins
				'' + lib.optionalString (harnesses ? "codex") ''
					${lib.optionalString (codexConfigAttrs != {}) "mkdir -p $out/codex && cp ${codexConfig} $out/codex/config.toml"}
				'' + lib.optionalString (harnesses ? "hermes-agent") ''
					# Hermes has no project-level skill discovery -- it only loads
					# $HERMES_HOME/skills (same agentskills.io SKILL.md format). The
					# materialize oneshot links these into /root/.hermes/skills; the
					# writes land in the VM overlay upper or container state PVC,
					# never the host.
					mkdir -p $out/hermes/skills
					${linkInto "$out/hermes/skills" "" skills}
					ln -s ${indexSkill} $out/hermes/skills/cogbox-plugins
				'' + lib.optionalString (rules != {}) ''
					# Harness-neutral rules digest: pi and hermes auto-inject an
					# AGENTS.md found in the cwd, and codex reads it natively -- none
					# of them has a native per-file rules dir like claude-code's
					# .claude/rules. Concatenate the merged rules into one AGENTS.md,
					# linked into ~/work only-if-absent by the materialize oneshot.
					# Path-scoped rules (paths: frontmatter) become always-on here,
					# same trade-off as opencode's instructions glob; the frontmatter
					# block itself is stripped (it is routing metadata, not prompt).
					{
						for f in $out/rules/*.md; do
							echo "<!-- cogbox rule: $(basename "$f" .md) -->"
							awk 'NR==1 && $0=="---" {fm=1; next} fm && $0=="---" {fm=0; next} !fm' "$f"
							echo
						done
					} > $out/AGENTS.md
				'' + lib.optionalString (cfg.packages != []) ''
					# Plugin tools on PATH: the container's brain-materialize prepends
					# $out/bin (via /root/work/.cogbox/brain/bin) to the guest PATH. On
					# the VM these are already baked into systemPackages, so this bin/ is
					# harmless-redundant there. Guarded so a plugin-less brain (the baked
					# base image's) keeps an out-path with no bin dir.
					ln -s ${pluginBin}/bin $out/bin
				'');

				# Materialize the brain into ~/work: create the ~/work symlink into
				# the persisted share, the .cogbox/brain RO store link, and per-leaf
				# child symlinks into each harness's native dirs (parents stay real
				# writable dirs so the harness can scaffold session state alongside).
				# Harness-agnostic: each layout is attempted, skipped if the brain
				# didn't build it. Offline-safe -- reads only closure-resident paths.
				# Container backend: the baked ${cogbox-brain} is BASE-only (the agent
				# image is built once, plugin-less). Resolve $brain by rebuilding it
				# from THIS instance's composition flake -- the SAME
				# `--override-input userExtensions <composition>` path the VM runner
				# rebuild takes (cogbox-launch.sh) -- and fall back to the baked base
				# brain when the instance has no plugins or the rebuild fails
				# (offline / eval error), so the sandbox always boots. Best-effort
				# throughout; nix's stderr flows to the unit journal. COGBOX_INSTANCE
				# is forwarded into the unit (PassEnvironment); ${self}/${nixpkgs} are
				# the image's baked flake + nixpkgs sources.
				brainResolveContainer = ''
					brain=${cogbox-brain}
					inst="''${COGBOX_INSTANCE:-default}"
					icd="''${XDG_CONFIG_HOME:-${stateRoot}/config}/cogbox/instances/$inst"
					pcount=0
					if [ -f "$icd/config.json" ]; then
						pcount=$(${pkgs.jq}/bin/jq -r '(.plugins // []) | length' "$icd/config.json" 2>/dev/null || echo 0)
					fi
					if [ "$pcount" -gt 0 ] && [ -f "$icd/plugins-flake/flake.nix" ]; then
						# Resolve the composition's transitive tarball/narHash inputs from
						# the per-instance file:// cache `cogbox plugin add` populated
						# (require-sigs false: a local content-addressed cache is unsigned).
						subst=()
						[ -d "$icd/plugin-cache" ] && subst=(--option extra-substituters "file://$icd/plugin-cache" --option require-sigs false)
						# Narinfo count is the seed-health signal on fallback: 0 means the
						# worker-side prebuild never populated the plugin-cache, so the
						# egress-less rebuild below had nothing to substitute from.
						nnar=$(ls "$icd/plugin-cache"/*.narinfo 2>/dev/null | wc -l || echo 0)
						echo "cogbox-brain: rebuilding per-instance brain ($pcount plugin(s)) for instance '$inst'" >&2
						# Evaluate the `-container` config, NOT the VM `${configName system}`.
						# cogboxBrain is target-INDEPENDENT (same runCommandLocal in both), but
						# the VM config imports microvm.nixosModules.microvm, which forces the
						# `microvm` flake input's SOURCE tree -- unfetchable offline in a
						# fail-closed sandbox, aborting the eval and silently dropping the whole
						# guest half. The `-container` (mkContainer) config omits microvm.
						# OFFLINE-CLEAN: the `-container`
						# brain eval now force-reads ZERO github flake input SOURCE trees.
						# microvm/nix-mcp/llm-agents are not forced here, and the last
						# holdout -- nixfs, previously imported unconditionally in
						# cogboxModules -- has been fully dropped. Only nixpkgs and
						# illustris-lib (both seeded in the baked agent image) are touched,
						# so a cold fail-closed pod can rebuild the brain without network.
						if out=$(${pkgs.nix}/bin/nix build --no-link --print-out-paths \
								--extra-experimental-features "nix-command flakes" \
								"''${subst[@]}" \
								--override-input userExtensions "path:$icd/plugins-flake" \
								--override-input userExtensions/user/nixpkgs "path:${nixpkgs}" \
								"path:${self}#nixosConfigurations.${configName system}-container.config.system.build.cogboxBrain"); then
							first=$(printf '%s\n' "$out" | grep -m1 '^/nix/store/' || true)
							if [ -n "$first" ] && [ -e "$first" ]; then
								brain="$first"
								echo "cogbox-brain: using per-instance brain $brain" >&2
								rm -f "$icd/brain.fallback" || true
							else
								echo "cogbox-brain: rebuild produced no out-path; using baked base brain (plugin-cache narinfos: $nnar)" >&2
								printf 'time=%s reason=%s narinfos=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" no-out-path "$nnar" > "$icd/brain.fallback" || true
							fi
						else
							echo "cogbox-brain: rebuild failed; using baked base brain (see prior nix log; plugin-cache narinfos: $nnar, 0 = worker seed never populated the cache)" >&2
							printf 'time=%s reason=%s narinfos=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" rebuild-failed "$nnar" > "$icd/brain.fallback" || true
						fi
					else
						# No plugin composition -> the baked base brain IS the correct
						# brain; clear any stale fallback marker left by a prior
						# plugin-era boot so it can't false-positive later.
						rm -f "$icd/brain.fallback" 2>/dev/null || true
					fi'';
				brainMaterializeScript = pkgs.writeShellScript "cogbox-brain-materialize" ''
					set -e
					${if isContainer then brainResolveContainer else "brain=${cogbox-brain}"}
					WORK=/var/lib/cogbox/work
					mkdir -p "$WORK/.cogbox"
					ln -sfn "$WORK" /root/work
					ln -sfn "$brain" "$WORK/.cogbox/brain"

					linkleaves() {  # $1 = brain subdir, $2 = dest dir
						[ -d "$1" ] || return 0
						mkdir -p "$2"
						for leaf in "$1"/*; do
							[ -e "$leaf" ] || continue
							ln -sfn "$leaf" "$2/$(basename "$leaf")"
						done
					}

					# claude-code: native skills/agents/commands/rules
					linkleaves "$brain/claude/skills"   "$WORK/.claude/skills"
					linkleaves "$brain/claude/agents"   "$WORK/.claude/agents"
					linkleaves "$brain/claude/commands" "$WORK/.claude/commands"
					linkleaves "$brain/rules"           "$WORK/.claude/rules"
					if [ -e "$brain/claude/settings.json" ]; then
						mkdir -p "$WORK/.claude"
						ln -sfn "$brain/claude/settings.json" "$WORK/.claude/settings.json"
					fi
					# project .mcp.json only when the user has none (never clobber)
					if [ -e "$brain/claude/.mcp.json" ] && [ ! -e "$WORK/.mcp.json" ]; then
						ln -sfn "$brain/claude/.mcp.json" "$WORK/.mcp.json"
					fi

					# opencode: config via OPENCODE_CONFIG; native skills/agents/commands
					linkleaves "$brain/opencode/skills"   "$WORK/.opencode/skills"
					linkleaves "$brain/opencode/agents"   "$WORK/.opencode/agents"
					linkleaves "$brain/opencode/commands" "$WORK/.opencode/commands"

					# codex + pi: skills under .agents/skills (codex resolves it from
					# ~, pi from cwd/ancestors -- the launchers cd to ~/work, and
					# /root/work -> $WORK, so both see this same tree). codex global
					# config.toml only if absent.
					linkleaves "$brain/agents/skills" "$WORK/.agents/skills"
					if [ -e "$brain/codex/config.toml" ] && [ ! -e /root/.codex/config.toml ]; then
						mkdir -p /root/.codex
						install -m600 "$brain/codex/config.toml" /root/.codex/config.toml || true
					fi

					${lib.optionalString (harnesses ? "hermes-agent") ''
						mkdir -p /root/.hermes/{cron,sessions,logs,memories}
					''}
					# hermes-agent: after its managed runtime skeleton exists, link skills
					# into $HERMES_HOME/skills. These writes land in the VM overlay upper
					# or container's per-instance state PVC, never the host home.
					linkleaves "$brain/hermes/skills" /root/.hermes/skills

					# Harness-neutral AGENTS.md (pi + hermes inject it from the cwd,
					# codex reads it natively): linked THROUGH the stable brain path
					# so it tracks brain rebuilds, and only-if-absent so a user's own
					# AGENTS.md is never clobbered. A dangling link that is ours
					# (rules removed by a plugin change) is dropped, not left broken.
					if [ -L "$WORK/AGENTS.md" ] && [ ! -e "$WORK/AGENTS.md" ] \
						&& [ "$(readlink "$WORK/AGENTS.md")" = ".cogbox/brain/AGENTS.md" ]; then
						rm -f "$WORK/AGENTS.md"
					fi
					if [ -e "$brain/AGENTS.md" ] && [ ! -e "$WORK/AGENTS.md" ]; then
						ln -sfn .cogbox/brain/AGENTS.md "$WORK/AGENTS.md"
					fi
				'';

				# Pre-accept Claude Code workspace trust for ~/work (both /root/work
				# and the /var/lib/cogbox/work it resolves to, since Node's cwd
				# resolves the symlink) and reconcile stale pre-migration project
				# keys. Replaces the per-plugin cogbox-claude-trust units. Also seeds
				# bypassPermissionsModeAccepted -- see the block above claudeStubScript,
				# which carries the full rationale for both backends.
				brainTrustScript = pkgs.writeShellScript "cogbox-brain-trust" ''
					set -eu
					f=/root/.claude.json
					[ -s "$f" ] || echo '{}' > "$f"
					${pkgs.jq}/bin/jq '
						.projects["/var/lib/cogbox/work"].hasTrustDialogAccepted = true
						| .projects["/root/work"].hasTrustDialogAccepted = true
						| del(.projects["/var/lib/cogbox"])
						| del(.projects["/var/lib/cogbox/home"])${lib.optionalString isVm ''

						| .hasCompletedOnboarding = true
						| .bypassPermissionsModeAccepted = true''}
					' "$f" > "$f.tmp"
					# Write THROUGH $f rather than `mv` onto it: on the container backend
					# the claude-stub oneshot symlinks /root/.claude.json at the state PVC
					# (so config survives a restart), and a rename would replace that
					# symlink with an ephemeral regular file. `cat >` follows the symlink
					# to the PVC target; for the VM (a regular file) it is equivalent.
					cat "$f.tmp" > "$f" && rm -f "$f.tmp"
					chmod 600 "$f"
				'';

				# Container backend: seed instances/<COGBOX_INSTANCE>/config.json
				# (with the default network-rule seed) once at boot, so the
				# kubectl-exec'd control-plane verbs (rules/l7/plugin) have a config
				# to edit. `cogbox init`'s --init-only path is pure host-state
				# seeding -- on a fresh instance PLUGIN_COUNT is 0, so it never
				# rebuilds a runner or touches a VM. 'default' is reserved by
				# `cogbox init -n`, so the default instance omits -n (which writes
				# the same instances/default/config.json).
				cogboxInitScript = pkgs.writeShellScript "cogbox-init" ''
					set -eu
					inst="''${COGBOX_INSTANCE:-default}"
					cfg="''${XDG_CONFIG_HOME:-${stateRoot}/config}/cogbox/instances/$inst/config.json"
					if [ -f "$cfg" ]; then
						echo "cogbox-init: $cfg already present; skipping seed." >&2
						exit 0
					fi
					echo "cogbox-init: seeding config for instance '$inst'" >&2
					if [ "$inst" = "default" ]; then
						exec ${self.packages.${system}.cogbox-container}/bin/cogbox init -y
					else
						exec ${self.packages.${system}.cogbox-container}/bin/cogbox init -y -n "$inst"
					fi
				'';

				# Container backend: per-user Claude auth stub-staging
				# cogworx's reconcile sets the
				# marker file on the state PVC when it binds the owner's `claude-oauth`
				# setup-token into the enforcer (and clears it on disconnect); this
				# oneshot makes the guest's ~/.claude/.credentials.json match, so
				# claude-code boots "logged-in but tokenless" exactly when -- and only
				# when -- the owner has connected Claude. The enforcer stamps the real
				# Bearer over the inert stub; the real token never reaches the agent.
				#
				# ~/.claude{,.json} are backed by the state PVC (symlinks below) so both
				# the staged stub AND the harness's own config/history survive a
				# container restart (closes Phase 0). The marker + the stub also live
				# on the PVC, so a restart re-stages from the persisted marker. The
				# marker path + unit name are matched by convention with cogworx
				# (control-plane convention).
				claudeStubScript = pkgs.writeShellScript "cogbox-claude-stub" ''
					set -eu
					persist=${stateRoot}/claude-home
					cdir="$persist/.claude"
					cjson="$persist/.claude.json"
					marker=${stateRoot}/claude-oauth.bound

					mkdir -p "$cdir"
					chmod 700 "$persist" "$cdir"
					# claude-code gates INTERACTIVE startup on hasCompletedOnboarding in
					# ~/.claude.json (observed on 2.1.191): without it the first-run
					# wizard runs, and its "Select login method" step reads as an auth
					# prompt -- a dead end in the sandbox, where the wizard's OAuth hosts
					# are never in the l7 allow-list. The credential file alone is NOT
					# enough for an interactive boot (`claude -p` works either way, which
					# is how this gap survived the launch e2e). So seed (absent) or merge
					# (present) the onboarding state: hasCompletedOnboarding is forced
					# true (claude-code clears it on /logout; the next oneshot run
					# re-forces it), theme is only defaulted (never clobbers a user's
					# choice). The merge is a SINGLE slurped jq read (no guard-then-merge
					# TOCTOU, and a multi-document file is rejected, not concatenated)
					# and NON-FATAL: cogworx restarts this unit mid-session while
					# claude-code may be rewriting the file through the symlink, and a
					# torn read must neither kill the oneshot before the stub verb below
					# runs nor seed-reset away the user's config -- on any parse/shape
					# failure the file is left untouched (claude-code's own
					# corrupt-config handling deals with real rot). brain-trust later
					# enriches the same file (workspace trust).
					#
					# bypassPermissionsModeAccepted rides along for the same reason, and is
					# forced the same way. It records that the harness's first-run consent
					# dialog has been answered; unseeded, the `c` launcher stops on a fresh
					# sandbox at an interactive "1. No, exit / 2. Yes, I accept" prompt and
					# never reaches the REPL (bare `claude` is unaffected, which is how it
					# stayed hidden). Note it is a TOP-LEVEL key read off the global config
					# getter -- NOT a .projects[...] key like the trust dialog brain-trust
					# seeds -- so it belongs here and not under a project path. It must be
					# set on BOTH branches below: an existing config that only gets the
					# merge would keep gating. The dialog is long-standing, not new to
					# 2.1.220 (same occurrence counts in the 2.1.214 bundle).
					#
					# Posture note, since this pre-answers a warning dialog: it changes
					# nothing about what the agent may do. The launcher already requests
					# that mode unconditionally, and cogbox's containment is the sandbox
					# boundary (nftables floor, l4/l7 enforcer, guest isolation), never the
					# harness's own in-process prompts -- the sibling harnesses are set up
					# the same way on purpose (see the codex launcher flags and opencode's
					# OPENCODE_PERMISSION). The key also VANISHES after first run: the
					# harness migrates the acceptance into
					# userSettings.skipDangerousModePermissionPrompt and strips it, and
					# either source satisfies the check, so re-forcing it each boot is a
					# no-op and an absent key in a USED config is not a failed seed.
					seed='{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true,"theme":"dark"}'
					if [ -e "$cjson" ]; then
						if merged=$(${pkgs.jq}/bin/jq -es 'if length == 1 and (.[0] | type == "object") then .[0] | .hasCompletedOnboarding = true | .bypassPermissionsModeAccepted = true | .theme //= "dark" else error("not a single object") end' "$cjson" 2>/dev/null); then
							printf '%s\n' "$merged" > "$cjson.tmp" && mv "$cjson.tmp" "$cjson" || rm -f "$cjson.tmp"
						fi
					else
						printf '%s\n' "$seed" > "$cjson"
					fi
					chmod 600 "$cjson"
					# /root/.claude{,.json} may pre-exist as REAL files/dirs (the image
					# home skel / claude-code's own init runs before this oneshot). `ln
					# -sfn` against an existing DIR NESTS the link inside it
					# (/root/.claude/.claude -> ...) instead of replacing it, so the staged
					# stub lands at the wrong path and claude-code reports "Not logged in".
					# Drop any non-symlink first; on later boots the link already exists
					# (-L true) so ln -f just refreshes it.
					[ -L /root/.claude ] || rm -rf /root/.claude
					ln -sfn "$cdir" /root/.claude
					[ -L /root/.claude.json ] || rm -rf /root/.claude.json
					ln -sfn "$cjson" /root/.claude.json

					# Stage (marker present) or remove (absent) the redacted stub. The
					# verb single-sources the stub sentinel from the secret module and
					# never writes a real token.
					${self.packages.${system}.cogbox-container}/bin/cogbox __claude-stub "$cdir" "$marker"
				'';

				# VM backend variant of the claude-stub reconcile. The container
				# claudeStubScript above is NOT reusable verbatim on the VM: its
				# ${stateRoot} marker/home paths are ephemeral on the VM (only
				# /var/lib/cogbox, the 9p mount, persists) and ~/.claude is an OVERLAY
				# mount the harness owns (the symlink dance would fight it). So this
				# variant only reconciles the cred file, against the marker on the
				# persistent mount, and -- crucially -- differs from the container in
				# how it reads an ABSENT marker:
				#
				#   marker ABSENT  -> UNMANAGED: a standalone single-host-user VM whose
				#     launcher staged its OWN redacted placeholder identity
				#     launcher staged its own redacted placeholder identity. Leave it
				#     untouched -- deleting it
				#     would break that model's on-the-wire injection.
				#   marker == "0"  -> cogworx MANAGED, owner DISCONNECTED: drop the stub
				#     (overlay whiteout over the launcher placeholder) so claude-code
				#     falls back to in-guest /login (fail-closed).
				#   marker present, not "0" -> cogworx MANAGED, owner CONNECTED: stage the
				#     redacted sentinel (the pod-side proxy stamps the real Bearer over
				#     it); the real token never enters the guest.
				#
				# The sentinel is single-sourced through the verb (never hardcoded in
				# this shell); only the removal is done inline. cogworx writes the
				# marker host-side on the 9p SOURCE and restarts this oneshot (and it
				# re-runs at every boot, so the persisted marker survives a restart).
				claudeStubScriptVm = pkgs.writeShellScript "cogbox-claude-stub-vm" ''
					set -eu
					marker=/var/lib/cogbox/claude-oauth.bound
					[ -e "$marker" ] || exit 0
					if [ "$(cat "$marker" 2>/dev/null || true)" = "0" ]; then
						rm -f /root/.claude/.credentials.json
					else
						${self.packages.${system}.cogbox-container}/bin/cogbox __claude-stub /root/.claude "$marker"
					fi
				'';
			in {
				nixpkgs.config.allowUnfree = true;

				# Discovered-unit name collisions across cogbox.contents roots fail
				# the build, plugin-agnostically attributed. (Explicit-name
				# collisions across plugins are caught for free by the module
				# system's attrsOf merge; the add-time lint pre-empts both.)
				assertions = (map (c: {
					assertion = false;
					message = "cogbox: duplicate discovered ${c} across cogbox.contents roots; rename one (units share a flat namespace) or use an explicit cogbox.* override.";
				}) discoveredCollisions)
				++ lib.optional (mcpViolations != []) {
					assertion = false;
					message = "cogbox.mcp servers may only set command/args/env/url/headers; rejected: ${lib.concatStringsSep ", " mcpViolations}. MCP auth goes through host-side inject, never inline.";
				};

				# Point login-shell TLS tools at the L7 CA bundle too (the
				# harness launchers also bake these in for non-login `cogbox
				# ssh -- c` invocations).
				environment.variables = l7CaEnv;
				# environment.variables reaches login shells only. The gateway's
				# sshd runs `UsePAM yes`, so a non-interactive `ssh host cmd`
				# exec (VS Code Remote-SSH's transport) sources pam_env but NOT a
				# login shell -- it would otherwise get no CA env. Mirror the CA
				# trust into sessionVariables (delivered via pam_env) so TLS tools
				# work over exec sessions too. NixOS merges sessionVariables
				# across modules, so this coexists with nix-ld's own NIX_LD*
				# entries below (disjoint keys).
				environment.sessionVariables = l7CaEnv;

				# nix-ld lets dynamically-linked, non-Nix ELF binaries run in the
				# sandbox: VS Code Remote-SSH downloads a prebuilt glibc `node`
				# (vscode-server) and extension host that expect a standard
				# /lib64/ld-linux loader, which a pure-Nix guest lacks. The module
				# sets environment.ldso (the /lib64 stub), NIX_LD, and
				# NIX_LD_LIBRARY_PATH via environment.sessionVariables -- again
				# pam_env-delivered, so it reaches the exec sessions the server
				# runs under. The stock default library set (zlib, openssl, curl,
				# systemd, stdenv.cc.cc, ...) covers vscode-server's node; these
				# extras cover common VS Code extension native binaries.
				programs.nix-ld.enable = true;
				programs.nix-ld.libraries = with pkgs; [ stdenv.cc.cc.lib icu libsecret ];

				# Container target DNS: the kubelet writes /etc/resolv.conf (cluster
				# DNS, e.g. `nameserver 10.96.0.10`) into the pod and manages it at
				# runtime -- it is NOT an environment.etc entry. NixOS's resolvconf
				# default-enables resolvconf.service, which runs `openresolv -u` at
				# boot and regenerates /etc/resolv.conf from the (empty)
				# networking.nameservers, leaving it nameserver-less -> DNS broken.
				# Disable resolvconf for the container so the kubelet-provided file is
				# preserved (nothing else here touches /etc/resolv.conf). mkForce
				# guards against any other module flipping it back on; gated to the
				# container so the VM runner is byte-identical.
				networking.resolvconf.enable = lib.mkIf isContainer (lib.mkForce false);

				# VM target DNS: NO PUBLIC FALLBACK RESOLVER, EVER.
				#
				# The guest's own resolver is always link-scope and always comes
				# from the host: passt/SLIRP puts a nameserver in its DHCP offer
				# (the host's resolver on a local/k8s launch, the intercepted
				# `--dns-forward` handle where COGBOX_GUEST_RESOLVER is set), and
				# what that answers is by construction what the HOST resolves --
				# internal names included. The microvm target enables networkd,
				# which default-enables systemd-resolved, which arrives carrying
				# systemd's compiled-in FallbackDNS list (1.1.1.1, 8.8.8.8,
				# 9.9.9.9, ...) at GLOBAL scope. That list is not a safety net
				# here, it is a LEAK: any window where the link scope has no DNS
				# yet or its server is marked bad sends the query NAME -- an
				# internal name -- to a third-party resolver, and turns an
				# internal-DNS outage into an ordinary-looking NXDOMAIN instead
				# of a visible failure. An empty list means such a lookup fails,
				# loudly, which is the correct answer for a sandbox whose entire
				# egress story is mediated by the host.
				#
				# `""` (not `[]`): settings.Resolve is the freeform systemd-ini
				# surface, and an empty LIST renders no line at all, which is
				# indistinguishable from unset -- the defect itself. The empty
				# STRING renders `FallbackDNS=`, which is what overrides the
				# compiled-in list. Same reasoning, same spelling as the GCE
				# host half in gce/cogbox-host.nix.
				#
				# Ungated by target although only the VM has resolved enabled
				# (the container's /etc/resolv.conf is kubelet-managed and this
				# module turns resolvconf off for it above): the resolved module
				# emits nothing when disabled, so the container toplevel stays
				# byte-identical, and if resolved were ever enabled there it
				# would want this pin too.
				services.resolved.settings.Resolve.FallbackDNS = "";

				# Container web-terminal locale. The web terminal attaches via
				# `kubectl exec -- env ... tmux ...` (cogworx's terminal attach),
				# which sources NO login shell and inherits NO /etc/locale.conf, so
				# without a UTF-8 LANG in the container env LC_CTYPE stays C (ASCII)
				# and tmux/claude-code render as degraded boxes. The cogworx pod env +
				# baked OCI Env set LANG=C.UTF-8; this makes that locale resolvable.
				# C.UTF-8 is a glibc builtin, so restricting supportedLocales to it
				# keeps the multi-hundred-MB glibcLocales archive out of the closure
				# instead of building "all". Gated to the container; the VM is untouched.
				i18n.defaultLocale = lib.mkIf isContainer "C.UTF-8";
				i18n.supportedLocales = lib.mkIf isContainer [ "C.UTF-8/UTF-8" ];

				# Container web-terminal TUI colors. The outer `kubectl exec` forces
				# TERM=xterm-256color, but tmux's default default-terminal is the
				# 8-color "screen", so a TUI INSIDE a pane (claude-code) would still
				# see TERM=screen and render in 8 colors. Advertise a 256-color,
				# truecolor-capable terminal to pane processes. The tmux-256color
				# terminfo entry ships with ncurses (a tmux dependency, already in the
				# image closure). cogworx launches tmux with `-f /etc/tmux.conf` so
				# this is loaded regardless of tmux's compiled sysconfdir. Gated to the
				# container; the VM's host-side tmux is unaffected.
				environment.etc."tmux.conf" = lib.mkIf isContainer {
					text = ''
						set -g default-terminal "tmux-256color"
						set -ga terminal-overrides ",*256col*:Tc"
					'';
				};

				# nscd is the lone unit that goes "degraded" in the unprivileged
				# container: NixOS default-enables it, but it cannot write its cache
				# (EROFS) here, so `systemctl is-system-running` reports degraded on an
				# otherwise healthy boot. The sandbox resolves users from a static
				# passwd/group (glibc builtin `files` NSS) and DNS via the
				# kubelet-managed /etc/resolv.conf (glibc builtin `dns` NSS), so the
				# NSS cache buys nothing. mkForce overrides the NixOS default-on; gated
				# to the container so the VM keeps its default nscd.
				services.nscd.enable = lib.mkIf isContainer (lib.mkForce false);
				# NixOS routes EXTERNAL NSS modules (here only nss-systemd, for the
				# `systemd` userdb / DynamicUser) through nscd, so it asserts nscd-on
				# whenever system.nssModules is non-empty. The sandbox needs neither
				# DynamicUser nor the systemd userdb -- root and DNS resolve via the
				# glibc builtin `files`/`dns` sources, which need no module -- so drop
				# the external modules in lockstep with disabling nscd. mkForce []
				# clears the systemd contribution; gated to the container (the VM keeps
				# nss-systemd + nscd untouched).
				system.nssModules = lib.mkIf isContainer (lib.mkForce []);

				# Container under a userns (hostUsers:false): NixOS stage-2 activation
				# re-applies its hardened mount options to the special filesystems the
				# OCI runtime/kubelet already mounted (/proc, /dev, /dev/pts, /dev/shm)
				# with `mount -o remount`. A SYS_ADMIN confined to a non-initial userns
				# cannot change flags on a superblock owned by the init userns, so the
				# remount EPERMs; the specialfs snippet has no `|| true`, so its ERR
				# trap makes `activate` exit non-zero and wedges the boot
				# (CrashLoopBackOff). Override specialfs to make ONLY the already-mounted
				# (remount) branch non-fatal: in a NON-userns container (today's live
				# deploy) the remount still SUCCEEDS and applies nosuid/noexec/nodev
				# exactly as upstream -- zero behavior change; only under a userns does
				# it fall through to "keep the runtime's mount as-is". The fresh-mount
				# branch (/run tmpfs, /run/keys ramfs -- userns-mountable and NOT
				# runtime-provided) stays FATAL so a genuinely missing mount errors
				# loudly (same "no silent || true" stance as the cgroup fix in a87dc47).
				# Sources the upstream earlyMountScript so the special-fs set can never
				# drift. Gated to the container; the VM/microvm path is byte-identical.
				system.activationScripts.specialfs = lib.mkIf isContainer (lib.mkForce ''
					specialMount() {
						local device="$1"
						local mountPoint="$2"
						local options="$3"
						local fsType="$4"

						if mountpoint -q "$mountPoint"; then
							mount -t "$fsType" -o "remount,$options" "$device" "$mountPoint" || true
						else
							mkdir -p "$mountPoint"
							chmod 0755 "$mountPoint"
							mount -t "$fsType" -o "$options" "$device" "$mountPoint"
						fi
					}
					source ${config.system.build.earlyMountScript}
				'');

				# Enabled on BOTH targets. The VM keeps its historical loopback
				# key-auth path (see below); the container adds a
				# certificate-authenticated sshd the cogworx SSH gateway dials with
				# a short-lived user cert (cogbox-sshd-ca staging the CA + principals).
				services.openssh.enable = true;
				# Auth hardening forced on BOTH targets. root has an EMPTY password on
				# the guest (VM serial-console UX), so password/empty-password/keyboard-
				# interactive auth MUST be unusable over the wire; root logs in by key
				# (VM) or user cert (container) only. mkForce so a NixOS default or a
				# plugin's full NixOS module can never re-enable them.
				services.openssh.settings = {
					PasswordAuthentication = lib.mkForce false;
					KbdInteractiveAuthentication = lib.mkForce false;
					PermitEmptyPasswords = lib.mkForce false;
					PermitRootLogin = lib.mkForce "prohibit-password";
					# `cogbox ssh` pins to a single key with IdentitiesOnly +
					# IdentityAgent=none (see zig/src/cli/verbs/ssh.zig), so its
					# default path makes exactly one auth attempt and can't exhaust
					# the limit. The generous cap is kept for the --no-auto-keys
					# opt-out path, where ssh falls back to the user's agent and
					# ~/.ssh keys and a busy agent could otherwise burn through the
					# default 6 attempts before a working key is reached. This guest
					# is a local, ephemeral, single-user sandbox (sshd bound to
					# 127.0.0.1), so a generous cap is safe. The k8s gateway path gets
					# a tight cap below (MaxAuthTries keyed per target in the shared
					# block), the local VM keeps 50.
				} // lib.optionalAttrs (isContainer || isVm) {
					# The gateway authenticates with a user certificate signed by a
					# cogworx-held CA; trust that CA and require the cert's principal
					# to match this instance (AuthorizedPrincipalsFile lists exactly
					# the instance ID). BOTH cluster-launched targets get this: the
					# container reads the CA/principal from pod env (cogbox-sshd-ca),
					# the VM reads them from the 9p-persistent state that cogworx
					# stages before boot (/var/lib/cogbox/.config, seeded by the k8s
					# pod entrypoint). The paths differ per target; everything else is
					# shared. (A purely-local `cogbox` VM leaves these files absent ->
					# no trusted CA -> cert auth simply never succeeds, fail-closed,
					# and plain authorized_keys still works via load-ssh-keys.)
					TrustedUserCAKeys = if isContainer then "/etc/ssh/trusted_user_ca.pub" else "/var/lib/cogbox/.config/ssh-ca.pub";
					AuthorizedPrincipalsFile = if isContainer then "/etc/ssh/principals/%u" else "/var/lib/cogbox/.config/ssh-principals/%u";
					# The gateway only needs local (client-initiated) port forwards to
					# reach in-sandbox services; deny everything else.
					AllowTcpForwarding = "local";
					AllowStreamLocalForwarding = "no";
					GatewayPorts = "no";
					X11Forwarding = false;
					# Permit ssh-agent forwarding so in-sandbox tools can reuse the
					# user's keys (e.g. git push). sshd only sets the ceiling here; the
					# gateway's short-lived cert (permit-agent-forwarding) is the actual
					# per-connection gate, driven by cogworx's COGWORX_SSH_AGENT_FORWARDING
					# (default on) -- with that off the sshd allowance is simply unused.
					AllowAgentForwarding = true;
					PermitTunnel = "no";
					# The cluster gateway/`cogbox ssh` hop makes exactly one
					# cert/key attempt, so a tight cap is correct there; a purely-
					# local VM keeps the generous cap for the --no-auto-keys agent
					# fallback (see the base comment above).
					MaxAuthTries = if isContainer then 3 else 50;
					LoginGraceTime = 20;
					ClientAliveInterval = 30;
					ClientAliveCountMax = 4;
					AllowUsers = [ "root" ];
				};
				# Container sshd binds all interfaces so the gateway pod can reach it;
				# the VM keeps the module default (reached only via the QEMU loopback
				# forward on 127.0.0.1:2222).
				services.openssh.listenAddresses = lib.mkIf isContainer [
					{ addr = "0.0.0.0"; port = 22; }
				];
				# Persist the sandbox host key so the gateway's TOFU host-key pin
				# survives restarts (a rotating key would break the pin on every
				# boot). The container persists on the state PVC (cogbox-container-
				# state creates the 0700 dir); the VM persists on the 9p-backed
				# /var/lib/cogbox mount (cogbox-vm-sshd-prep creates the 0700 dir and
				# pre-generates the key BEFORE sshd, ordered after var-lib-cogbox.mount,
				# so sshd never races the late 9p mount). A purely-local `cogbox` VM
				# gets the same persistent key under its host data dir.
				services.openssh.hostKeys = lib.mkIf (isContainer || isVm) [
					{ type = "ed25519"; path = if isContainer then "${stateRoot}/ssh/ssh_host_ed25519_key" else "/var/lib/cogbox/ssh/ssh_host_ed25519_key"; }
				];

				environment.systemPackages = with pkgs; [
					git
					curl
					jq
					vim
					ncdu
					tmux
					htop
					# certutil: cogbox-l7-trust.service imports the per-instance MITM
					# CA into root's NSS db with it (so Chromium/Playwright trust the
					# terminate tier); also handy for inspecting that trust.
					nss.tools

					# Generic CLI toolkit, broadly useful to any in-guest agent or
					# task. Grouped by purpose; jq/curl/git are above.
					# search / files
					ripgrep fd bat sd
					# data wrangling
					yq-go duckdb miller dasel gron datamash jo
					# http / dns / web
					xh websocat dnsutils htmlq pup
					# shell glue (moreutils brings sponge/ts/chronic/ifne/vipe; for
					# parallelism `xargs -P` is already present, so no GNU parallel)
					moreutils
				]
				++ lib.concatMap (h: [ h.package (mkLauncher h) ]) (lib.attrValues harnesses)
				++ lib.optionals hasNixMcp [
					nix-mcp.packages.${system}.default
				]
				++ lib.optionals (system != "riscv64-linux") [
					bpftrace
				]
				# Container backend: the cogbox CLI itself, so cogworx can
				# `kubectl exec <pod> -c agent -- cogbox <verb> -n <name>` to drive
				# the control-plane verbs (init/rules/l7/remap/plugin) on the running
				# sandbox. Lands `cogbox`/`cbx` in /run/current-system/sw/bin (on the
				# agent-image PATH). The VM never carries the CLI in-guest (it is the
				# host-side launcher there), so gate it to the container.
				++ lib.optional isContainer self.packages.${system}.cogbox-container
				# Plugin-contributed tools (cogbox.packages). On the VM the runner
				# rebuild bakes these into the guest closure here; on the container
				# they reach PATH via cogbox-brain's $out/bin instead (the baked base
				# image is plugin-less), so this line is an inert no-op there.
				++ cfg.packages;

				# Expose the materialized plugin "brain" as a build product so the
				# container can rebuild it per-instance at boot. config.cogbox (hence
				# this derivation) is target-independent, so it is the SAME drv on the
				# VM and container configs; adding it here does not touch the microvm
				# runner closure (which references neither system.build.cogboxBrain nor
				# the toplevel's full system.build). The container's
				# cogbox-brain-materialize builds
				# `nixosConfigurations.${configName}.config.system.build.cogboxBrain`
				# with `--override-input userExtensions <instance composition>` -- the
				# exact mechanism cogbox-launch.sh uses to fold per-instance plugins
				# into the VM runner.
				system.build.cogboxBrain = cogbox-brain;

				microvm = lib.mkIf isVm {
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
					# A human (HMP) QEMU monitor on a per-instance socket, for
					# `cogbox monitor`. The microvm module already wires a QMP
					# control socket (qemu.socket -> -qmp); this is the separate
					# readline monitor humans actually want to type at. The
					# ${runtimeDir} sentinel is sed-rewritten to the live $RUNTIME
					# by cogbox-launch.sh, same as the fw_cfg paths below.
					qemu.extraArgs = [
						# Re-emit `-cpu` to mask RDRAND/RDSEED off the guest CPU while
						# KEEPING KVM accel. microvm.nix's own runner emits
						# `-enable-kvm -cpu host,+x2apic,-sgx`; setting the microvm.cpu
						# option would override that string BUT the module then also
						# drops `-enable-kvm` (qemu.nix gates it on `cpu == null`), so we
						# cannot use it. Instead we append a second `-cpu` here: qemu
						# honors the LAST `-cpu` (verified: no warning, last wins) and
						# `-enable-kvm` stays. Without this the guest kernel wedges at
						# early boot ("Poking KASLR using RDRAND RDTSC...") because
						# executing RDRAND can stall the vcpu under nested KVM;
						# masking it forces the RDTSC entropy
						# fallback. Mirrors microvm's own base string so only rdrand/rdseed
						# differ. VM-only (isVm); the container has no qemu args.
						"-cpu"
						"host,+x2apic,-sgx,-rdrand,-rdseed"
						"-monitor"
						"unix:${runtimeDir}/monitor.sock,server,nowait"
					] ++ lib.concatMap (p: [
						"-fw_cfg"
						"name=opt/${tag p.harness p.pathkey},file=${sentinel p.harness p.pathkey}"
					]) fwCfgPaths ++ [
						# System (instance-level, not per-harness) fw_cfg carrying
						# the L7 terminate CA cert. ALWAYS emitted -- the launcher
						# stages an empty stub when terminate is off -- so the guest
						# image stays byte-identical regardless of L7 state.
						"-fw_cfg"
						"name=opt/system-l7ca,file=${runtimeDir}/system-l7ca"
					];
				};
				# re-run the L7 trust assembly whenever the enforcer (re)publishes
				# its CA, so a CA that arrives after cogbox-l7-trust's boot window still
				# gets trusted (else allowed HTTPS silently fails until the next reboot).
				systemd.paths.cogbox-l7-trust = lib.mkIf isContainer {
					description = "Watch the enforcer-published L7 CA and rebuild the trust bundle";
					wantedBy = [ "multi-user.target" ];
					pathConfig = {
						PathChanged = l7CaSource;
						Unit = "cogbox-l7-trust-refresh.service";
					};
				};


				# Per-fw_cfg copy services. Each one materializes a single
				# host file (auth token, etc.) into its guest path at boot.
				# fw_cfg copy units are a VM-only mechanism (the container has no
				# /sys/firmware/qemu_fw_cfg); gate the whole generated set off so
				# the container drops them. optionalAttrs (not mkIf) so the keys
				# vanish entirely rather than evaluate to dropped definitions.
				systemd.services = lib.optionalAttrs isVm (lib.listToAttrs (map (p:
					lib.nameValuePair "${p.harness}-${p.pathkey}" {
						description = "Copy ${p.harness}/${p.pathkey} from fw_cfg";
						wantedBy = [ "multi-user.target" ];
						# Order BEFORE sshd: otherwise a client that connects the moment
						# sshd is up (ttyd -> cogbox ssh ... c) can read this file while
						# the cp below is still writing it, which surfaces as
						# "<file> contains invalid JSON" on the first harness launch
						# (later launches see the finished file). Mirrors cogbox-l7-trust.
						before = [ "multi-user.target" "sshd.service" ];
						serviceConfig = {
							Type = "oneshot";
							# Write to a temp then rename so the target appears atomically
							# (whole file or nothing), never a half-written partial.
							ExecStart = "/bin/sh -c 'cp /sys/firmware/qemu_fw_cfg/by_name/opt/${tag p.harness p.pathkey}/raw ${p.guest}.tmp && chmod ${p.mode} ${p.guest}.tmp && mv ${p.guest}.tmp ${p.guest}'";
							RemainAfterExit = true;
						};
					}
				) fwCfgPaths)) // {
					cogbox-brain-materialize = {
						description = "Materialize the cogbox plugin brain into ~/work";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						after = [ stateUnit ]
							++ lib.optional isContainer "cogbox-init.service"
							++ lib.optional (isVm && harnesses ? "codex") "${utils.escapeSystemdPath "/root/.codex"}.mount"
							# In the VM, Hermes skills are linked into the overlay upper;
							# linking before the mount would write to the covered rootfs.
							++ lib.optional (isVm && harnesses ? "hermes-agent") "${utils.escapeSystemdPath "/root/.hermes"}.mount";
						requires = [ stateUnit ]
							++ lib.optional (isVm && harnesses ? "hermes-agent") "${utils.escapeSystemdPath "/root/.hermes"}.mount";
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = brainMaterializeScript;
						} // lib.optionalAttrs isContainer {
							# COGBOX_INSTANCE picks which instance's composition flake the
							# brain rebuilds from; XDG_CONFIG_HOME locates it. systemd does
							# not forward PID1's env, so set/pass them explicitly.
							Environment = [ "XDG_CONFIG_HOME=${stateRoot}/config" ];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
						};
					};
					cogbox-brain-trust = {
						description = "Pre-accept Claude Code workspace trust for ~/work";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						after = [ stateUnit "cogbox-brain-materialize.service" ]
							++ lib.optional isContainer "cogbox-claude-stub.service"
							++ lib.optional (isVm && harnesses ? "claude-code") "claude-code-auth.service";
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = brainTrustScript;
						};
					};
					# Crash-loop guard for the per-instance full toplevel. agentInit writes
					# a toplevel.attempt marker (the out-path) BEFORE exec'ing a per-instance
					# toplevel; this oneshot clears it once THIS booted system is confirmed to
					# be that recorded toplevel. If the toplevel fails to boot, systemd never
					# reaches here, the marker persists, and the next boot falls back to the
					# baked base (quarantining the unbootable toplevel until a re-add produces a
					# new out-path). Only clears when the running system IS the recorded
					# toplevel, so a crash that fell back to base keeps the quarantine.
					cogbox-toplevel-confirm = lib.mkIf isContainer {
						description = "Clear the per-instance toplevel crash-loop marker on a good boot";
						wantedBy = [ "multi-user.target" ];
						after = [ stateUnit "cogbox-brain-materialize.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							Environment = [ "XDG_CONFIG_HOME=${stateRoot}/config" ];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
						};
						script = ''
							inst="''${COGBOX_INSTANCE:-default}"
							icd="${stateRoot}/config/cogbox/instances/$inst"
							rec="$icd/toplevel.path"
							[ -f "$rec" ] || exit 0
							recorded="$(${pkgs.coreutils}/bin/head -n2 "$rec" | ${pkgs.coreutils}/bin/tail -n1)"
							cur="$(${pkgs.coreutils}/bin/readlink -f /run/current-system)"
							if [ -n "$recorded" ] && [ "$cur" = "$recorded" ]; then
								${pkgs.coreutils}/bin/rm -f "$icd/toplevel.attempt"
							fi
						'';
					};
					# Boot reconcile for the per-instance full toplevel. The add-time toplevel
					# prebuild only runs on the LIVE agent pod (running-instance adds); a
					# stopped/fresh add (worker pod) writes no toplevel record, so its
					# non-package module surface wouldn't take effect. This oneshot -- run AFTER
					# boot completes (multi-user.target => egress up, and the base is already in
					# the image store) -- builds + records the toplevel from the already-
					# materialized composition, so the NEXT Start boots the per-instance
					# toplevel. It also self-heals across image bumps. `after multi-user.target`
					# makes it truly background: the sandbox is Ready (the readiness probe gates
					# on brain-materialize, well before this) while the reconcile builds. The
					# `reconcile` verb no-ops fast when nothing changed (composition-hash guard)
					# and removes the record when no plugins remain (revert to base). Best-effort.
					cogbox-toplevel-reconcile = lib.mkIf isContainer {
						description = "Reconcile + record the per-instance full toplevel for the next boot";
						wantedBy = [ "multi-user.target" ];
						after = [ "multi-user.target" ];
						serviceConfig = {
							Type = "oneshot";
							# cogbox resolves the instance config from $XDG_CONFIG_HOME/cogbox/...
							# (else $HOME/.config, which is /.config with HOME unset -> "no config
							# found" -> the || true swallows it -> silent no-op). systemd does not
							# forward PID1's env, so set it explicitly (same as brain-materialize).
							Environment = [ "XDG_CONFIG_HOME=${stateRoot}/config" ];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
						};
						script = ''
							inst="''${COGBOX_INSTANCE:-}"
							cbx=${self.packages.${system}.cogbox-container}/bin/cogbox
							# The plugin verb resolves the instance from -n only (not the env), and
							# rejects the reserved name "default"; omit -n for the default instance.
							# Best-effort: never fail the unit -- a miss just leaves the last record.
							if [ -n "$inst" ] && [ "$inst" != "default" ]; then
								"$cbx" plugin reconcile -n "$inst" || true
							else
								"$cbx" plugin reconcile || true
							fi
						'';
					};
					# Assemble the L7 CA trust bundle: system store + the injected
					# per-instance MITM CA (when terminate is active). Always
					# produces ${l7CaBundle} so the CA env vars resolve even when
					# terminate is off (then it is just the system bundle).
					cogbox-l7-trust = {
						description = "Assemble the L7 terminate-tier CA trust bundle";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# cogbox-l7-trust.path/refresh restarts this unit when the enforcer
							# CA lands; if that happens while the boot run is still in its bounded
							# CA wait, the restart SIGTERMs it. For Type=oneshot systemd does NOT
							# treat SIGTERM as success, so the superseded (idempotent) initial run
							# would otherwise surface as a failed unit -- mark SIGTERM successful.
							SuccessExitStatus = "SIGTERM";
							ExecStart = pkgs.writeShellScript "cogbox-l7-trust" ''
								set -e
								mkdir -p /run/cogbox
								raw=${l7CaSource}${lib.optionalString isContainer ''
								  # The enforcer sidecar mints the CA then publishes the cert to the
								  # ca-pub mount asynchronously. BLOCK (bounded, ~60s) so the bundle + NSS
								  # import below actually include it and harness egress never opens before
								  # the CA is trusted. The nft divert is fail-closed meanwhile, so a timeout
								  # here degrades to the system bundle, never opens an untrusted hole.
								  for _ in $(seq 1 300); do
								  	[ -s "$raw" ] && break
								  	sleep 0.2
								  done''}
								ca=/run/cogbox/l7-ca.crt
								bundle=${l7CaBundle}
								sys=/etc/ssl/certs/ca-certificates.crt
								[ -r "$sys" ] || sys=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
								: > "$ca"
								[ -r "$raw" ] && cp "$raw" "$ca" || true
								if [ -s "$ca" ] && grep -q "BEGIN CERTIFICATE" "$ca"; then
									cat "$sys" "$ca" > "$bundle"
								else
									cp "$sys" "$bundle"
								fi
								chmod 0644 "$bundle"

								# NSS-based clients -- notably Chromium / Playwright, which
								# ignore the CA env vars AND the bundle file above -- read
								# trusted roots from the per-user NSS db. Mirror the CA into
								# root's db so browser-driven plugins trust terminate-tier
								# leaves too. Idempotent across boots and terminate on/off:
								# (re)create the db (the cert9.db guard avoids a certutil -N
								# re-init prompt), drop any prior copy, re-add only when a real
								# CA is present. Best-effort (set +e): the env-var bundle still
								# covers non-NSS clients, so a certutil hiccup must degrade
								# browser trust, never fail this boot-ordered unit.
								set +e
								db=/root/.pki/nssdb
								mkdir -p "$db"
								[ -e "$db/cert9.db" ] || ${pkgs.nss.tools}/bin/certutil -N --empty-password -d "sql:$db"
								${pkgs.nss.tools}/bin/certutil -D -n cogbox-l7-ca -d "sql:$db" 2>/dev/null
								if [ -s "$ca" ] && grep -q "BEGIN CERTIFICATE" "$ca"; then
									${pkgs.nss.tools}/bin/certutil -A -n cogbox-l7-ca -t "C,," -i "$ca" -d "sql:$db"
								fi
								set -e
							'';
						};
					};
					# self-heal: the enforcer publishes its CA to l7CaSource
					# asynchronously; a slow (cold image pull) enforcer pod can land it
					# AFTER cogbox-l7-trust's ~60s boot window, leaving the agent on the
					# bare system bundle so every allowed HTTPS fails until reboot
					# (fail-closed, no leak). The .path above runs this on the CA's
					# (re)appearance; restarting the trust unit re-runs its idempotent
					# bundle+NSS assembly, now with the CA present. Container-only
					# (the VM delivers the CA via fw_cfg before boot).
					cogbox-l7-trust-refresh = lib.mkIf isContainer {
						description = "Rebuild the L7 CA trust bundle when the enforcer CA (re)appears";
						serviceConfig = {
							Type = "oneshot";
							ExecStart = "${pkgs.systemd}/bin/systemctl restart cogbox-l7-trust.service";
						};
					};
					load-ssh-keys = lib.mkIf isVm {
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
					# VM backend: prepare the persistent sshd host key + the gateway
					# CA/principal files on the 9p-backed /var/lib/cogbox BEFORE sshd
					# starts. The container backend does the equivalent from pod env
					# (cogbox-sshd-ca); the VM cannot read pod env, so cogworx's k8s
					# pod entrypoint stages the real CA/principal into this same 9p
					# source before boot and sshd reads them directly (TrustedUserCAKeys
					# /AuthorizedPrincipalsFile point here). Ordered after the 9p mount
					# so the (late) mount is up, and before sshd so the key + dirs exist.
					cogbox-vm-sshd-prep = lib.mkIf isVm {
						description = "Prepare the VM's persistent sshd host key + gateway CA/principal dirs";
						wantedBy = [ "multi-user.target" ];
						before = [ "sshd.service" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "cogbox-vm-sshd-prep" ''
								set -eu
								# Persistent host-key dir (0700 so the private key is not
								# group/world readable) + the gateway CA/principal dir.
								mkdir -p /var/lib/cogbox/ssh /var/lib/cogbox/.config/ssh-principals
								chmod 700 /var/lib/cogbox/ssh
								# Pre-generate the persistent host key here rather than leaving
								# it to sshd's own keygen, so it exists on the (late) 9p mount
								# before sshd regardless of the module's keygen timing. A
								# stable key is what keeps the gateway's TOFU pin valid across
								# restarts.
								key=/var/lib/cogbox/ssh/ssh_host_ed25519_key
								[ -s "$key" ] || ${pkgs.openssh}/bin/ssh-keygen -t ed25519 -N "" -C cogbox-vm -f "$key"
								# Fail-closed CA/principal: cogworx stages the REAL files into
								# this dir (host-side, before boot) when the gateway is enabled.
								# When it is not (a purely-local VM, or the gateway is off),
								# seed EMPTY files so sshd never reads a missing
								# TrustedUserCAKeys/AuthorizedPrincipalsFile -- empty CA -> no
								# cert validates; empty principals -> no principal matches. A
								# real file already staged by cogworx is left untouched.
								[ -e /var/lib/cogbox/.config/ssh-ca.pub ] || : > /var/lib/cogbox/.config/ssh-ca.pub
								[ -e /var/lib/cogbox/.config/ssh-principals/root ] || : > /var/lib/cogbox/.config/ssh-principals/root
							'';
						};
					};
					# The VM host key lives on the late 9p mount; order sshd after
					# it (and after the prep unit that creates the dir + key) so sshd
					# never starts before the key it must read is present.
					sshd = lib.mkIf isVm {
						after = [ "var-lib-cogbox.mount" "cogbox-vm-sshd-prep.service" ];
						requires = [ "cogbox-vm-sshd-prep.service" ];
					};
					# The module's separate host-key generator must also wait for
					# the 9p mount + prep, or it races the late mount; with the key
					# already generated it finds it present and does nothing.
					sshd-keygen = lib.mkIf isVm {
						after = [ "var-lib-cogbox.mount" "cogbox-vm-sshd-prep.service" ];
					};
					harness-overlay-img = lib.mkIf isVm {
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
								# (Re)format when the image is MISSING or does not hold a
								# valid ext4 filesystem. A first-boot mkfs interrupted by a
								# pod recreate (the ~4min boot can outrun the ~5.2min k8s
								# startup-probe deadline) leaves the file present but with a
								# zeroed/garbage superblock; the old `[ ! -f ]`-only guard
								# then skipped reformatting on every later boot, wedging the
								# guest in emergency mode (VFS: Can't find ext4 filesystem ->
								# /var/lib/harness-rw never mounts -> no sshd -> recreate
								# loop, no self-heal). `dumpe2fs -h` reads ONLY the
								# superblock, so a valid (even fully populated) overlay is
								# preserved -- no data loss -- while a missing or corrupt one
								# is rebuilt.
								if [ ! -f "$img" ] || ! ${pkgs.e2fsprogs}/bin/dumpe2fs -h "$img" >/dev/null 2>&1; then
									size="128M"
									sizefile=/var/lib/cogbox/.config/overlay-size
									if [ -f "$sizefile" ]; then
										size=$(cat "$sizefile")
									fi
									${pkgs.coreutils}/bin/truncate -s "$size" "$img"
									${pkgs.e2fsprogs}/bin/mkfs.ext4 -q -F "$img"
								fi
							'';
						};
					};

					harness-setup-dirs = lib.mkIf isVm {
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

					resize-store-overlay = lib.mkIf isVm {
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

					# Container backend: prepare the mounted state volume and make
					# ~/work and enabled harness state resolve into it before brain
					# materialization. The brain/trust oneshots hardcode /var/lib/cogbox
					# as the data dir, so symlink it into the mounted state too.
					cogbox-container-state = lib.mkIf isContainer {
						description = "Prepare mounted state + ~/work resolution (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "cogbox-brain-materialize.service" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "cogbox-container-state" ''
								set -e
								mkdir -p ${cogboxData} ${stateRoot}/config ${stateRoot}/ssh /run/cogbox
								# sshd writes the persisted host key here (0700 so the
								# private key is not group/world readable).
								chmod 700 ${stateRoot}/ssh
								ln -sfn ${cogboxData} /var/lib/cogbox
								${lib.optionalString (harnesses ? "hermes-agent") ''
									${hermesHomeHelper}/bin/cogbox-hermes-home ${stateRoot}/hermes-home /root/.hermes
								''}
							'';
						};
					};

					# Container backend: seed the per-instance config.json before the
					# brain materializes (and before any kubectl-exec'd verb edits it).
					# Ordered after the state symlink and before brain-materialize.
					cogbox-init = lib.mkIf isContainer {
						description = "Seed the per-instance cogbox config (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "cogbox-brain-materialize.service" ];
						after = [ "cogbox-container-state.service" ];
						requires = [ "cogbox-container-state.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# systemd does not forward PID1's env to services. XDG_CONFIG_HOME
							# /COGBOX_DATA/HOME are baked constants; COGBOX_INSTANCE is the
							# runtime per-sandbox name the pod sets (unset -> "default").
							Environment = [
								"HOME=/root"
								"XDG_CONFIG_HOME=${stateRoot}/config"
								"COGBOX_DATA=${cogboxData}"
							];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
							ExecStart = cogboxInitScript;
						};
					};

					# Container backend: reconcile the redacted Claude stub credential
					# from the per-instance marker cogworx sets/clears (step 5b). Ordered
					# after the state symlink and BEFORE brain-materialize/brain-trust/login
					# so the ~/.claude{,.json} PVC symlinks + the stub are in place before
					# brain-trust writes ~/.claude.json and before a terminal opens.
					# Re-run on connect/disconnect by cogworx (systemctl restart) and at
					# every boot (restart persistence from the PVC marker).
					cogbox-claude-stub = lib.mkIf (isContainer || isVm) {
						description = "Stage/remove the redacted Claude stub credential"
							+ lib.optionalString isContainer " (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" "cogbox-brain-materialize.service" "cogbox-brain-trust.service" ];
						# stateUnit resolves per target (cogbox-container-state.service /
						# var-lib-cogbox.mount). On the VM the verb writes
						# .credentials.json into the /root/.claude OVERLAY, so that mount
						# must be up first (a write before it lands on the covered rootfs).
						after = [ stateUnit ]
							++ lib.optional (isVm && harnesses ? "claude-code") "${utils.escapeSystemdPath "/root/.claude"}.mount";
						requires = [ stateUnit ]
							++ lib.optional (isVm && harnesses ? "claude-code") "${utils.escapeSystemdPath "/root/.claude"}.mount";
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# The container verb resolves XDG/HOME/COGBOX_DATA to locate
							# the state root; the VM variant takes explicit path args and
							# needs only HOME.
							Environment = if isContainer then [
								"HOME=/root"
								"XDG_CONFIG_HOME=${stateRoot}/config"
								"COGBOX_DATA=${cogboxData}"
							] else [
								"HOME=/root"
							];
							ExecStart = if isContainer then claudeStubScript else claudeStubScriptVm;
						};
					};

					# Container backend: install the SSH user-CA trust anchor and this
					# instance's authorized-principals file BEFORE sshd starts. The
					# gateway presents a short-lived user certificate signed by the
					# cogworx-held CA; sshd (TrustedUserCAKeys) verifies the signature
					# and (AuthorizedPrincipalsFile) that the cert carries this
					# instance's name as a principal. Fail closed: if the CA is not
					# supplied no anchor is written (no cert can validate); if the
					# instance name is empty the principals file is empty (no principal
					# matches). sshd reads both files at connection time, so ordering
					# this unit before sshd is sufficient.
					cogbox-sshd-ca = lib.mkIf isContainer {
						description = "Install the SSH user-CA trust anchor + per-instance principals (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "sshd.service" ];
						after = [ "cogbox-container-state.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# systemd does not forward PID1's env; the pod sets these and
							# they are passed through explicitly (mirrors COGBOX_INSTANCE
							# elsewhere).
							PassEnvironment = [ "COGBOX_SSH_CA_PUB" "COGBOX_SSH_PRINCIPAL" "COGBOX_INSTANCE" ];
							ExecStart = pkgs.writeShellScript "cogbox-sshd-ca" ''
								set -eu
								mkdir -p /etc/ssh/principals ${stateRoot}/ssh
								chmod 700 ${stateRoot}/ssh
								ca="''${COGBOX_SSH_CA_PUB:-}"
								if [ -n "$ca" ]; then
									printf '%s\n' "$ca" > /etc/ssh/trusted_user_ca.pub
									chmod 644 /etc/ssh/trusted_user_ca.pub
								fi
								# Exactly one principal, keyed on a GLOBALLY-UNIQUE id
								# (cogworx sets COGBOX_SSH_PRINCIPAL to the full instance ID,
								# accountID-name). Falls back to the bare COGBOX_INSTANCE name
								# only if the manifest has not set it yet -- but note the bare
								# name is unique only per-account, so a shared CA + bare-name
								# principal would let a captured cert replay across tenants;
								# the dedicated principal env closes that. Empty when neither
								# is set -> no cert principal can match -> sshd denies.
								principal="''${COGBOX_SSH_PRINCIPAL:-''${COGBOX_INSTANCE:-}}"
								printf '%s\n' "$principal" > /etc/ssh/principals/root
								chmod 644 /etc/ssh/principals/root
							'';
						};
					};
				};

				virtualisation.docker.enable = lib.mkIf isVm true;

				fileSystems = lib.mkIf isVm ({
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
				));
			})
		];
	in {
		# The GCE bake seam. `packages.gce-image` builds the DEFAULT host config,
		# whose cogworx.gce.controlCAPublicKey is empty -- fail-closed, and
		# therefore NOT publishable: sshd would trust no control CA and every
		# certificate cogworxd mints would be refused, so every instance created
		# from it wedges in Booting. Baking a real image means overriding that
		# option, and these two outputs are the supported ways to do it (there is
		# no other: the default config is constructed inside this flake and takes
		# no arguments).
		#
		#   nix build --impure --expr '((builtins.getFlake "/path/to/cc-sandbox").lib.mkGceHost
		#     "x86_64-linux" { extraModules = [ { cogworx.gce.controlCAPublicKey = "ssh-ed25519 AAAA... control-ca"; } ]; }
		#   ).config.system.build.googleComputeImage'
		lib.mkGceHost = mkGceHost;
		nixosModules.gce-host = ./gce/cogbox-host.nix;

		packages = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			runner = self.nixosConfigurations.${configName system}.config.microvm.declaredRunner;
			# Container-native agent system (see mkContainer): the SAME guest
			# module tree with target = "container". Its toplevel/init boots
			# systemd PID1 in the agent-image below.
			containerSystem = mkContainer system "cogbox" {
				extraModules = cogboxModules system { target = "container"; };
			};
			containerToplevel = containerSystem.config.system.build.toplevel;
			# Registration (nix-store --dump-db format) for the WHOLE agent-image /nix
			# closure, baked into the image at /etc/cogbox/base-reginfo. The CoW seed
			# (cogworx's CoW-seed) `nix-store --load-db`s it into the frozen node lower
			# so the stopped-add worker can SUBSTITUTE the base closure from the lower over
			# local disk. Without a DB the lower
			# is store-paths-only and unusable as a substituter. rootPaths = the image
			# content root (containerToplevel; bashInteractive is already in its closure),
			# so the registration covers every path `cp -a /nix/.` puts in the lower. The
			# baked file is plain text (store-path strings already in the image closure), so
			# it adds no new closure.
			baseReginfo = pkgs.closureInfo { rootPaths = [ containerToplevel ]; };
			# Pre-systemd boot shim for the unprivileged agent pod
			# systemd PID1 cannot bring
			# itself up under a stock Kubernetes pod for two container-specific
			# reasons that must be fixed BEFORE exec'ing the NixOS init:
			#
			#  1. cgroup-v2 delegation. The kubelet mounts the pod's delegated
			#     /sys/fs/cgroup subtree READ-ONLY for a non-privileged container,
			#     so systemd cannot create its cgroup hierarchy and exits. Remount
			#     it read-write -- or, under a userns (hostUsers:false) where that
			#     remount EPERMs because the superblock is owned by the INIT userns,
			#     mount a FRESH pod-owned cgroup2 instead (a confined SYS_ADMIN may
			#     mount cgroup2 but may not change the init-userns mount's flags).
			#     This is namespaced to the pod's OWN delegated subtree (private
			#     cgroup namespace, cgroup root "0::/"), NOT the host root, and uses
			#     the single CAP_SYS_ADMIN the pod is granted for exactly this — no
			#     privileged, no /dev/kvm, no NET_ADMIN/RAW. systemd in container
			#     mode does NOT self-remount a ro cgroup (verified), so this is required.
			#  2. Writable /etc. dockerTools lays the NixOS toplevel's own /etc as
			#     a symlink into the immutable Nix store, so activation's setup-etc
			#     cannot populate it. Drop the symlink; NixOS then builds a fresh
			#     writable /etc on the overlay rootfs.
			#
			# Both are no-ops/best-effort if a future runtime delegates a writable
			# cgroup or the image stops baking /etc, so the shim degrades cleanly.
			# NB: at boot time PATH points only at /run/current-system/sw/bin (not
			# yet populated), so every command here MUST be an absolute store path.
			agentInit = pkgs.writeShellScript "cogbox-agent-init" ''
				# cgroup-v2: make the kubelet's read-only delegated /sys/fs/cgroup
				# writable so systemd PID1 can build its hierarchy. NON-userns: a
				# remount,rw works (the pod's host-level CAP_SYS_ADMIN owns the
				# superblock). Under a USERNS (hostUsers:false) that remount EPERMs --
				# a SYS_ADMIN confined to a non-initial userns cannot change mount
				# flags on the cgroup2 superblock, which is owned by the INIT userns --
				# so fall back to mounting a FRESH pod-owned cgroup2 over it: cgroup2
				# is userns-mountable, the new superblock is owned by THIS userns
				# (hence writable), and the pod's private cgroup namespace scopes it to
				# the pod's own subtree. No silent "|| true": if neither works the boot
				# log says so loudly instead of dying as an opaque systemd exit 255.
				if ! ${pkgs.util-linux}/bin/mount -o remount,rw /sys/fs/cgroup 2>/dev/null; then
					${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null \
						|| echo "cogbox-agent-init: WARNING: /sys/fs/cgroup stayed read-only (remount,rw and a fresh cgroup2 mount both failed); systemd will likely fail to boot" >&2
				fi
				[ -L /etc ] && ${pkgs.coreutils}/bin/rm -f /etc || true

				# Boot the per-instance toplevel (the plugin's FULL NixOS module folded in)
				# when a valid record exists, else the baked plugin-less base. The record +
				# closure are seeded WITH egress at plugin-add (prebuildToplevelLocal); boot
				# has none, so realise the recorded out-path OFFLINE from the per-instance
				# file:// plugin-cache on the state PVC (the base is already in the image
				# store, so only the plugin's delta is fetched). Any miss -- no record, rev
				# mismatch (image bump), or an unrealisable path -- falls back to the baked
				# base, so the sandbox always boots. Pre-systemd: /etc/nix/nix.conf does not
				# exist yet, so pass nix options explicitly and RESTRICT substituters to the
				# local cache (no network attempt on the egress-less boot); read the RAW PVC
				# path (the /var/lib/cogbox symlink oneshot has not run yet).
				top=${containerToplevel}
				inst="''${COGBOX_INSTANCE:-default}"
				icd="/var/lib/cogbox-state/config/cogbox/instances/$inst"
				rec="$icd/toplevel.path"
				attempt="$icd/toplevel.attempt"
				if [ -f "$rec" ]; then
					rev="$(${pkgs.coreutils}/bin/head -n1 "$rec")"
					out="$(${pkgs.coreutils}/bin/head -n2 "$rec" | ${pkgs.coreutils}/bin/tail -n1)"
					if [ "$rev" = "${self}" ] && [ -n "$out" ]; then
						# Crash-loop guard: an attempt marker for THIS out-path means a
						# previous boot exec'd it but it never reached the confirm oneshot
						# (systemd failed to boot) -- do NOT re-boot the unbootable toplevel;
						# fall back to the baked base so the sandbox stays usable (tools still
						# land via the brain). A re-add yields a new out-path (marker mismatch),
						# so a fixed plugin IS retried; the confirm oneshot clears the marker
						# once the recorded toplevel boots successfully.
						if [ -f "$attempt" ] && [ "$(${pkgs.coreutils}/bin/cat "$attempt" 2>/dev/null)" = "$out" ]; then
							echo "cogbox-agent-init: per-instance toplevel $out failed a prior boot; booting baked base" >&2
						elif ${pkgs.nix}/bin/nix-store --realise "$out" --option substituters "file://$icd/plugin-cache" --option require-sigs false --option build-users-group "" >/dev/null 2>&1 && [ -x "$out/init" ]; then
							${pkgs.coreutils}/bin/mkdir -p "$icd" 2>/dev/null || true
							echo "$out" > "$attempt" 2>/dev/null || true
							top="$out"
							echo "cogbox-agent-init: booting per-instance toplevel $out" >&2
						else
							echo "cogbox-agent-init: per-instance toplevel not realisable offline; booting baked base" >&2
						fi
					else
						echo "cogbox-agent-init: toplevel record stale/invalid (image bump?); booting baked base" >&2
					fi
				fi
				exec "$top/init"
			'';
			# Space-separated enabled-harness names, baked into cogbox-launch.sh's
			# `HARNESSES=(@harnesses@)` so the launcher's set can never drift from
			# what the VM was built with (single source of truth: mkHarnesses +
			# enableCodex).
			harnessNames = lib.concatStringsSep " " (lib.attrNames (mkHarnesses system pkgs));
			# Build a cogbox package: the Zig CLI binary at $out/bin/cogbox,
			# the LD_PRELOAD filter at $out/lib/libnetfilter.so, and the
			# substituted bash launch script at $out/libexec/cogbox-launch.sh.
			# bin/cogbox is wrapped to expose runtime deps on PATH and to
			# point COGBOX_LAUNCH_SCRIPT at its sibling libexec script.
			mkCogbox = runner': pkgs.runCommand "cogbox" {
				nativeBuildInputs = [ pkgs.makeWrapper ];
				meta = { mainProgram = "cogbox"; };
			} ''
				mkdir -p $out/bin $out/lib $out/libexec
				cp ${self.packages.${system}.cogbox-tools}/bin/cogbox $out/bin/cogbox
				chmod +w $out/bin/cogbox
				cp ${self.packages.${system}.cogbox-tools}/lib/libnetfilter.so $out/lib/libnetfilter.so

				# L7 terminate-tier enforcement addon for mitmproxy.
				cp ${./l7-mitm-addon.py} $out/libexec/l7-mitm-addon.py
				cp ${./cogbox-launch.sh} $out/libexec/cogbox-launch.sh
				chmod +w $out/libexec/cogbox-launch.sh
				substituteInPlace $out/libexec/cogbox-launch.sh \
					--replace-fail "@runtimeDir@" "${runtimeDir}" \
					--replace-fail "@runner@" "${runner'}" \
					--replace-fail "@netfilter@" "$out/lib/libnetfilter.so" \
					--replace-fail "@cogbox@" "$out/bin/cogbox" \
					--replace-fail "@harnesses@" "${harnessNames}" \
					--replace-fail "@mitmdump@" "${pkgs.mitmproxy}/bin/mitmdump" \
					--replace-fail "@l7addon@" "$out/libexec/l7-mitm-addon.py" \
					--replace-fail "@flock@" "${pkgs.util-linux}/bin/flock" \
					--replace-fail "@flakeSource@" "${self}" \
					--replace-fail "@nixpkgsSource@" "${nixpkgs}"
				chmod +x $out/libexec/cogbox-launch.sh
				
				# Container enforcer supervisor (sidecar PID1). Reuses the same cogbox
				# binary + mitmdump + L7 addon as the launch script; NO VM tokens.
				cp ${./cogbox-enforce.sh} $out/libexec/cogbox-enforce.sh
				chmod +w $out/libexec/cogbox-enforce.sh
				substituteInPlace $out/libexec/cogbox-enforce.sh \
					--replace-fail "@cogbox@" "$out/bin/cogbox" \
					--replace-fail "@mitmdump@" "${pkgs.mitmproxy}/bin/mitmdump" \
					--replace-fail "@l7addon@" "$out/libexec/l7-mitm-addon.py"
				chmod +x $out/libexec/cogbox-enforce.sh
				
				# nft REDIRECT divert init -- the nft-init sidecar's entrypoint. Standalone
				# POSIX sh (bare nft/awk resolved from the nft-init image PATH), so it
				# carries no @-substitutions; co-located here for provenance/debugging.
				cp ${./cogbox-nft-divert.sh} $out/libexec/cogbox-nft-divert.sh
				chmod +x $out/libexec/cogbox-nft-divert.sh

				wrapProgram $out/bin/cogbox \
					--set COGBOX_LAUNCH_SCRIPT $out/libexec/cogbox-launch.sh \
					--set COGBOX_ENFORCE_SCRIPT $out/libexec/cogbox-enforce.sh \
					--set-default COGBOX_FLAKE_SOURCE "${self}" \
					--set-default COGBOX_NIXPKGS_SOURCE "${nixpkgs}" \
					--prefix PATH : "${lib.makeBinPath (with pkgs; [
						coreutils gnused gnugrep jq diffutils nix bashInteractive openssh
					] ++ [ self.packages.${system}.passt-cc ])}"

				# `cbx` is a short alias for `cogbox`. The wrapper execs an
				# absolute path to .cogbox-wrapped (not $0) and the Zig CLI
				# ignores argv[0], so the symlink behaves identically.
				ln -s cogbox $out/bin/cbx
			'';
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

			# cogbox CLI for the container-native agent image: identical Zig
			# binary + launch script, but baked against a NON-store placeholder
			# runner so the heavy microvm runner closure (QEMU, guest kernel) is
			# NOT pulled into the agent image. The container IS the sandbox -- it
			# never launches a VM, so the only `cogbox` paths it exercises are the
			# control-plane verbs (init/rules/l7/remap/plugin) and `cogbox init`'s
			# --init-only host-state seeding, none of which dereference @runner@.
			# COGBOX_FLAKE_SOURCE/COGBOX_NIXPKGS_SOURCE stay baked (the in-container
			# per-instance brain rebuild below needs them).
			cogbox-container = mkCogbox "/var/empty/cogbox-container-has-no-vm-runner";

			# Container image for a single cogbox sandbox pod: bundles the cogbox
			# CLI so a Kubernetes control plane (e.g. cogworx) runs `cogbox start`
			# against /dev/kvm inside the pod. streamLayeredImage (not
			# buildLayeredImage) makes the image a build script that streams the
			# tarball on demand -- nothing multi-hundred-MB is realized into the
			# Nix store; pipe it to skopeo / `docker load` (see push-pod-image).
			cogbox-pod-image = pkgs.dockerTools.streamLayeredImage {
				name = "cogbox-pod";
				tag = "latest";
				# passt self-sandboxes by mounting a tmpfs at /tmp and pivot_root-ing
				# into it; streamLayeredImage creates no /tmp, so passt failed with
				# ENOENT and the guest VM booted with no networking. Provide /tmp.
				extraCommands = "mkdir -m 1777 -p tmp var/tmp";
				contents = [
					cogbox
					# nix's git+http(s)/ssh flake fetcher execs the `git` CLI; without it
					# `cogbox plugin add <git+...>` fails "executing git: No such file".
					# cacert + SSL_CERT_FILE (below) let the https variant verify TLS.
					pkgs.git
					# The worker pod pre-builds the microvm runner at plugin-add time and
					# pushes the closure to a binary cache so boot substitutes it instead
					# of rebuilding from source (cogbox plugin's COGBOX_RUNNER_PUSH path).
					pkgs.attic-client
					pkgs.cacert
					pkgs.bashInteractive
					pkgs.coreutils
					# `kubectl cp <local> <worker>:<dst>` (cogworx, the
					# STOPPED-instance archive-upload path) untars INTO this container, so it
					# needs `tar` on the exec PATH -- coreutils does NOT ship it, and without it
					# the cp fails "exec: tar: not found" before the plugin add runs. The agent
					# image gets tar from /run/current-system/sw/bin; the worker is a plain
					# userland, so add it explicitly.
					pkgs.gnutar
					# cogbox-launch.sh is `#!/usr/bin/env bash`; without /usr/bin/env
					# the kernel can't find the interpreter and `cogbox init` ExecvFails.
					pkgs.dockerTools.usrBinEnv
					# passt drops privileges to `nobody` and cogbox calls `id`; both
					# need /etc/passwd + /etc/group. fakeNss seeds root + nobody.
					pkgs.dockerTools.fakeNss
					# In-pod nix must BUILD the microvm runner when an instance has a
					# plugin: a no-plugin runner is the baked-in cache hit, but a
					# plugin's custom NixOS module makes a fresh closure. The pod has
					# no `nixbld` group, so nix's default `build-users-group = nixbld`
					# aborts every build -- empty it so nix builds single-user as root
					# (the pod is itself the isolation boundary). `sandbox = false`:
					# the build sandbox needs namespace/mount setup the pod doesn't
					# grant, and plugin builds are trusted-on-add. `substituters` makes
					# the standard leaf deps (nodejs, ...) substitute from the public
					# caches the pod is given egress to, so only the small
					# plugin-specific top is built from source. cogbox-launch.sh still
					# adds the per-instance PVC plugin-cache via `--extra-substituters`
					# (require-sigs false) on top of this.
					(pkgs.writeTextDir "etc/nix/nix.conf" (lib.concatStringsSep "\n" [
						"experimental-features = nix-command flakes"
						"build-users-group ="
						"sandbox = false"
						"substituters = https://cache.nixos.org https://cache.numtide.com"
						"trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
					] + "\n"))
				];
				config = {
					Entrypoint = [ "/bin/sh" ];
					Env = [ "PATH=/bin" "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
				};
			};

			# Container-native agent image:
			# the cogbox guest's NixOS userland booted as an UNPRIVILEGED
			# container -- no QEMU, no /dev/kvm, no privileged. Reuses the
			# streamLayeredImage builder from cogbox-pod-image, but the contents
			# are a full NixOS toplevel: /etc, users, /etc/nix/nix.conf, and CA
			# trust are generated by NixOS activation at boot, so -- unlike the
			# plain-userland cogbox-pod-image -- this image needs no fakeNss /
			# usrBinEnv / baked nix.conf / cacert layers (their equivalents are
			# mkContainer options). Entrypoint is systemd PID1 via the toplevel's
			# /init; it runs the reused brain/trust/l7-trust oneshots to
			# multi-user.target. cogbox-pod-image is deliberately left untouched
			# (the VM backend coexists).
			agent-image = pkgs.dockerTools.streamLayeredImage {
				name = "cogbox-agent";
				tag = "latest";
				# systemd PID1 + early units need a writable /tmp; streamLayeredImage
				# seeds none (same reason as cogbox-pod-image). Also bake root's home
				# /root: NixOS does not create it for a container, and creating a new
				# entry directly under / can be blocked by the runtime's rootfs
				# ownership -- so the reused brain-materialize/trust oneshots (which
				# write ~/work + dotfiles under /root) get a real, writable home.
				# Also drop the NixOS toplevel's baked /etc symlink (it points into
				# the read-only Nix store, so activation's setup-etc cannot populate
				# it); with it gone NixOS builds a fresh writable /etc on the overlay
				# rootfs at boot. The agent-init shim repeats this defensively at
				# runtime in case the whiteout does not survive the layering.
				# Bake a /bin/sh -> bash symlink: NixOS creates /bin/sh only during
					# activation (setupBinSh), but cogworx's CoW-store seed init container
					# runs `sh -c <script>` against THIS image BEFORE systemd/activation (to
					# seed the node-shared /nix lower + mount the per-instance overlay), so it
					# needs a shell at the raw-image /bin/sh. bashInteractive is root's login
					# shell, already in the toplevel closure. The seed script is otherwise
					# self-contained (globs coreutils/util-linux/grep out of the store), so
					# /bin/sh is the ONLY userland entry it needs baked here.
					extraCommands = "mkdir -m 1777 -p tmp var/tmp && mkdir -m 0700 -p root && rm -f etc && mkdir -p bin && ln -sf ${pkgs.bashInteractive}/bin/bash bin/sh && mkdir -p etc/cogbox && cp ${baseReginfo}/registration etc/cogbox/base-reginfo";
				# The store closure arrives via the toplevel (also referenced by
				# Entrypoint); no extra userland layers are needed.
				contents = [ containerToplevel ];
				config = {
					# Entrypoint is the pre-systemd shim (above), which fixes the
					# cgroup/-etc container quirks then exec's the NixOS systemd PID1.
					Entrypoint = [ "${agentInit}" ];
					# Mirror the cogworx k8s pod env so a
					# kubectl-exec'd `c`/`tmux`/`git` resolves identically whether or
					# not the pod also sets these. /run/current-system/sw/bin is
					# populated by NixOS activation (the harness launchers c/oc, tmux,
					# git all live there).
					Env = [
						"PATH=/run/current-system/sw/bin:/usr/bin:/bin"
						"XDG_CONFIG_HOME=/var/lib/cogbox-state/config"
						"COGBOX_DATA=/var/lib/cogbox-state/data/cogbox"
						"XDG_RUNTIME_DIR=/run/cogbox"
						"SSL_CERT_FILE=/run/cogbox/ca-bundle.crt"
						# UTF-8 locale for a `kubectl exec` (which sources no login
						# shell, so it does not pick up /etc/locale.conf): without this
						# LC_CTYPE stays C (ASCII) and tmux/claude-code render in
						# degraded boxes. C.UTF-8 is the glibc builtin the container
						# system sets as i18n.defaultLocale. Mirrors the cogworx pod env
						# so a direct/worker-pod exec inherits it even without the pod.
						"LANG=C.UTF-8"
						"LC_CTYPE=C.UTF-8"
						# NixOS stage-2 + systemd run in container mode only when the
						# `container` env var is set (nspawn sets it; containerd/k8s do
						# not). Without it stage-2 tries to remount / and mount host
						# special filesystems, all of which fail unprivileged. Set it
						# so the guest boots as a container, not a host.
						"container=oci"
					];
				};
			};
				# Container enforcer sidecar image (the L7 proxy/mitm control plane). Uses
				# the placeholder-runner cogbox (cogbox-container) so NO QEMU/microvm-runner
				# closure is pulled in; mitmdump + the L7 addon + cogbox-enforce.sh arrive via
				# that cogbox's closure (the @mitmdump@/@l7addon@ substitutions). The pod
				# overrides Entrypoint with `cogbox enforce -n <name>`. (passt-cc/libnetfilter
				# remain incidentally in the cogbox closure but are unused here.)
				enforcer-image = pkgs.dockerTools.streamLayeredImage {
					name = "cogbox-enforcer";
					tag = "latest";
					# mitmproxy/python + the supervisor write under /tmp; streamLayeredImage
					# seeds none (same as cogbox-pod-image). Provide it.
					extraCommands = "mkdir -m 1777 -p tmp var/tmp";
					contents = [
						cogbox-container          # cogbox CLI + cogbox-enforce.sh + mitmdump + L7 addon (closure)
						pkgs.cacert
						pkgs.bashInteractive
						pkgs.coreutils
						pkgs.gnugrep              # cogbox-enforce.sh greps the CA for a stray private key
						# cogbox-enforce.sh is `#!/usr/bin/env bash`; without /usr/bin/env the
						# kernel cannot find the interpreter.
						pkgs.dockerTools.usrBinEnv
						# mitmproxy drops privileges / calls id(); both need /etc/passwd + group.
						pkgs.dockerTools.fakeNss
					];
					config = {
					  # Pod sets command: ["cogbox","enforce","-n",<name>]; this is a sane default.
					  Entrypoint = [ "/bin/cogbox" ];
					  Env = [ "PATH=/bin" "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
					};
				};

				# nft REDIRECT divert init image -- the privileged native sidecar (NET_ADMIN/
				# NET_RAW). MINIMAL: just nftables + iproute2 + coreutils + /bin/sh + the
				# standalone divert script (entrypoint). NO cogbox/qemu/mitmproxy. The
				# separate-pod divert script uses nft alone -- the old cgroup-handshake
				# (find -inum + awk) is gone -- so gawk + findutils are dropped. The pod
				# sets no command, so the image Entrypoint runs the script directly; the
				# enforcer ClusterIP carve-out arrives via COGBOX_ENFORCER_IP/PORT env.
				nft-init-image = pkgs.dockerTools.streamLayeredImage {
					name = "cogbox-nft-init";
					tag = "latest";
					contents = [
						pkgs.nftables             # nft (loads the divert + fail-closed floor)
						pkgs.iproute2             # ip (the native-sidecar netns toolkit / debugging)
						pkgs.coreutils            # sleep/cat/printf for the script + entrypoint
						pkgs.dockerTools.binSh    # /bin/sh for the script's #!/bin/sh
						(pkgs.runCommand "cogbox-nft-divert" {} ''
							mkdir -p $out/bin
							cp ${./cogbox-nft-divert.sh} $out/bin/cogbox-nft-divert
							chmod +x $out/bin/cogbox-nft-divert
						'')
					];
					config = {
					  Entrypoint = [ "/bin/cogbox-nft-divert" ];
					  Env = [ "PATH=/bin" "COGBOX_DIVERT_PORT=18443" ];
					};
				};

		} // lib.optionalAttrs (system == "x86_64-linux") {
			# Test fixture: a cogbox wrapper baked against the
			# pre-built test-hello runner. Used by tests/cogbox.nix
			# Phase E to make the offline NixOS test machine's
			# `nix run --override-input userExtensions ...` resolve as a
			# cache hit instead of building the transitive .drv graph
			# (which would fail with no network).
			cogbox-test-hello = mkCogbox
				self.nixosConfigurations.cogbox-x86_64-test-hello.config.microvm.declaredRunner;
			# Phase Q analog: wrapper baked against the composition-shaped
			# runner (see cogbox-x86_64-test-plugin).
			cogbox-test-plugin = mkCogbox
				self.nixosConfigurations.cogbox-x86_64-test-plugin.config.microvm.declaredRunner;

			# The GCE backend image: a raw disk.raw wrapped in the sparse
			# gzipped tar `gcloud compute images create` imports. Building it
			# is an OPERATOR step (it boots a builder VM and produces a
			# multi-GB artifact), which is why nothing in `checks` depends on
			# it -- the checks assert the CLOSURE and the UNIT GRAPH of the
			# system this image contains, which is where the image invariants live.
			#
			# PHASE-0: nixpkgs' postVM tars with the default GNU format. Confirm `gcloud compute
			# images create` accepts it before the bake is called done.
			gce-image = self.nixosConfigurations.cogbox-x86_64-gce.config.system.build.googleComputeImage;
		});

		# `nix run .#push-pod-image [-- <registry-ref>]` streams the sandbox-pod
		# image straight into the destination registry. Supply the ref as the arg
		# or via $COGBOX_POD_REF (default is a placeholder); registry auth comes
		# from $REGISTRY_AUTH_FILE, else ~/.docker/config.json.
		apps = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			image = self.packages.${system}.cogbox-pod-image;
			agentImage = self.packages.${system}.agent-image;
			enforcerImage = self.packages.${system}.enforcer-image;
			nftInitImage = self.packages.${system}.nft-init-image;
		in {
			push-pod-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-pod-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_POD_REF:-registry.example.com/team/cogbox-pod:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-pod -> docker://$ref (auth: $authfile)" >&2
						${image} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-pod-image";
			};
			# `nix run .#push-agent-image [-- <registry-ref>]` streams the
			# container-native agent image into the destination registry. Supply
			# the ref as the arg or via $COGBOX_AGENT_REF (default is a
			# placeholder); auth from $REGISTRY_AUTH_FILE, else ~/.docker/config.json.
			push-agent-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-agent-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_AGENT_REF:-registry.example.com/team/cogbox-agent:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-agent -> docker://$ref (auth: $authfile)" >&2
						${agentImage} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-agent-image";
			};
			# `nix run .#push-enforcer-image [-- <ref>]` streams the enforcer sidecar
			# image into the destination registry. Ref via the arg or $COGBOX_ENFORCER_REF
			# (default a placeholder on registry.example.com); auth from
			# $REGISTRY_AUTH_FILE, else ~/.docker/config.json.
			push-enforcer-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-enforcer-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_ENFORCER_REF:-registry.example.com/team/cogbox-enforcer:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-enforcer -> docker://$ref (auth: $authfile)" >&2
						${enforcerImage} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-enforcer-image";
			};
			# `nix run .#push-nft-init-image [-- <ref>]` streams the nft-init sidecar
			# image. Ref via the arg or $COGBOX_NFT_INIT_REF (default a placeholder on
			# registry.example.com); auth as above.
			push-nft-init-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-nft-init-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_NFT_INIT_REF:-registry.example.com/team/cogbox-nft-init:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-nft-init -> docker://$ref (auth: $authfile)" >&2
						${nftInitImage} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-nft-init-image";
			};
		} // lib.optionalAttrs (system == "x86_64-linux") {
			# `nix run .#push-gce-image [-- <gs://bucket/prefix>]` stages the
			# GCE image tarball in GCS and registers it as a Compute image in a
			# family.
			#
			# This is the OPERATOR image-pipeline identity's job, never the
			# lifecycle credential's: the least-privilege model excludes
			# `images.create` plus GCS staging from the role cogworxd holds, so
			# a compromised lifecycle credential cannot substitute the trusted
			# half's own code. Run it with the pipeline identity's gcloud
			# credentials, not cogworxd's service-account key.
			#
			# IT TAKES THE IMAGE PATH AS INPUT and refuses to default to
			# `packages.gce-image`. That default was the whole hazard: the
			# packaged image is built from the flake's DEFAULT host config,
			# whose cogworx.gce.controlCAPublicKey is empty. Publishing is the one
			# step where that mistake becomes expensive, so this is where it
			# fails closed. See README ("Two things the image cannot supply").
			push-gce-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-gce-image";
					runtimeInputs = [ pkgs.google-cloud-sdk pkgs.coreutils ];
					text = ''
						bucket="''${1:-''${COGWORX_GCE_IMAGE_BUCKET:-gs://example-bucket/cogbox-gce}}"
						family="''${COGWORX_GCE_IMAGE_FAMILY:-cogbox-gce}"
						name="''${COGWORX_GCE_IMAGE_NAME:-$family-$(date -u +%Y%m%d%H%M%S)}"
						src="''${COGWORX_GCE_IMAGE_SRC:-}"
						if [ -z "$src" ]; then
							echo "push-gce-image: set COGWORX_GCE_IMAGE_SRC to the build output of a CA-BAKED image." >&2
							echo "  nix build --impure --expr '((builtins.getFlake \"/path/to/cogbox\").lib.mkGceHost \"x86_64-linux\" { extraModules = [ { cogworx.gce.controlCAPublicKey = \"ssh-ed25519 AAAA... cogworx-control-ca\"; } ]; }).config.system.build.googleComputeImage'" >&2
							echo "  COGWORX_GCE_IMAGE_SRC=./result nix run .#push-gce-image" >&2
							echo "This does NOT default to packages.gce-image: that one bakes no control CA, so sshd would trust nothing and every instance would wedge in Booting." >&2
							exit 1
						fi
						if [ -d "$src" ]; then
							src=$(echo "$src"/*.raw.tar.gz)
						fi
						[ -f "$src" ] || { echo "push-gce-image: no image tarball at $src" >&2; exit 1; }
						obj="$bucket/$(basename "$src")"
						echo "Staging $src -> $obj" >&2
						gcloud storage cp "$src" "$obj"
						echo "Creating image $name (family $family) from $obj" >&2
						gcloud compute images create "$name" \
							--source-uri="$obj" \
							--family="$family"
						# The control plane pins the IMMUTABLE NUMERIC ID, never
						# the name: deleting an image frees its name, so a
						# name pin would let the whole trusted half be replaced
						# while the recorded pin still matched. Print the id so
						# the operator records the right thing.
						gcloud compute images describe "$name" --format='value(id,name,selfLink)'
					'';
				}}/bin/push-gce-image";
			};
		});

		checks = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			hermesHomeHelper = mkHermesHomeHelper pkgs;
			containerStateScript = self.nixosConfigurations."${configName system}-container".config.systemd.services.cogbox-container-state.serviceConfig.ExecStart;
			# The two realized harness-config reconcile scripts, one per backend, for
			# harness-firstrun-flags below. Forcing the two small scripts rather than
			# a toplevel keeps that check cheap.
			containerHarnessConfScript = self.nixosConfigurations."${configName system}-container".config.systemd.services.cogbox-claude-stub.serviceConfig.ExecStart;
			vmHarnessConfScript = self.nixosConfigurations.${configName system}.config.systemd.services.cogbox-brain-trust.serviceConfig.ExecStart;
			# Every cogbox GUEST config that renders a resolved.conf, paired with
			# its name, for guest-dns-no-public-fallback below. Forcing the small
			# ini file rather than a toplevel keeps that check cheap. Today only
			# the microVM guest contributes: the container has resolved disabled
			# (kubelet owns its /etc/resolv.conf), so it renders no file.
			guestResolvedConfs = lib.concatMap (name: let
				etc = self.nixosConfigurations.${name}.config.environment.etc;
			in lib.optional (etc ? "systemd/resolved.conf") {
				inherit name;
				path = etc."systemd/resolved.conf".source;
			}) [ (configName system) "${configName system}-container" ];
			enabledHarnesses = mkHarnesses system pkgs;
			releaseHarnesses = {
				claude-code = enabledHarnesses.claude-code.package;
				opencode = enabledHarnesses.opencode.package;
				codex = inputs.llm-agents.packages.${system}.codex;
				hermes-agent = enabledHarnesses.hermes-agent.package;
				# pi is opt-out of the default image (enablePi above), so it is no longer
				# in enabledHarnesses. Reference the BASE numtide pi (not the overridden
				# one we've stopped shipping) so the release version gate stays a cache
				# hit and needs no npmjs egress -- mirrors how codex is handled above.
				pi = inputs.llm-agents.packages.${system}.pi;
			};
			# GCE backend image assertions (x86_64 only; nested virt is Intel
			# only). These are lazy let-bindings, forced only by the
			# x86_64-guarded checks at the bottom of this block.
			gceCfg = self.nixosConfigurations.cogbox-x86_64-gce.config;
			gceToplevel = gceCfg.system.build.toplevel;
			gceUnits = "${gceToplevel}/etc/systemd/system";
			# closureInfo over the toplevel is exactly what make-disk-image.nix
			# loads into the image's store DB, so asserting against it asserts
			# against what the booted VM can actually resolve offline.
			gceClosure = pkgs.closureInfo { rootPaths = [ gceToplevel ]; };
			gceFloorVerify = gceCfg.systemd.services.cogworx-floor.serviceConfig.ExecStartPost;
			gceFloorInstall = gceCfg.systemd.services.cogworx-floor.serviceConfig.ExecStart;
			gceSuperviseScript = gceCfg.systemd.services.cogworx-supervisor.serviceConfig.ExecStart;
			gceStateDiskScript = gceCfg.systemd.services.cogworx-state-disk.serviceConfig.ExecStart;
			gceResolverDeadlineScript = gceCfg.systemd.services.cogworx-resolver-deadline.serviceConfig.ExecStart;
			gceCogboxWrapper = gceCfg.cogworx.gce.cogboxPackage;
			# Stands in for the real cogbox binary so gce-cogbox-wrapper-env can
			# observe what the wrapper actually exported, without running a verb.
			gceWrapperEnvStub = pkgs.writeShellScript "cogbox-env-stub" ''
				printf 'XDG_CONFIG_HOME=%s\n' "''${XDG_CONFIG_HOME-<unset>}"
				printf 'COGBOX_DATA=%s\n' "''${COGBOX_DATA-<unset>}"
				printf 'XDG_RUNTIME_DIR=%s\n' "''${XDG_RUNTIME_DIR-<unset>}"
				printf 'COGBOX_PROXY_RUNAS=%s\n' "''${COGBOX_PROXY_RUNAS-<unset>}"
			'';
			# The bake seam of `lib.mkGceHost`, evaluated (not built) so the
			# runbook's one supported way to inject a control CA is asserted
			# rather than asserted-in-prose. A fictional key line: nothing parses
			# it, the check only proves it reaches sshd's TrustedUserCAKeys file.
			gceBakeCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEcontrolCAkeyFORtheFLAKEcheck control-ca";
			gceBakedCAText = (mkGceHost "x86_64-linux" {
				extraModules = [ { cogworx.gce.controlCAPublicKey = gceBakeCAKey; } ];
			}).config.environment.etc."ssh/cogworx-control-ca.pub".text;
			gceDefaultCAText = gceCfg.environment.etc."ssh/cogworx-control-ca.pub".text;
			# The MERGE-ABLE seam, exercised through the same bake path: a composed
			# profile's own user CA has to have somewhere to land, because
			# TrustedUserCAKeys itself is forced and a definition there loses
			# silently. Fictional key lines; nothing parses them.
			gceBakeExtraCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEfleetCAkeyFORtheFLAKEcheck fleet-ca";
			gceBakedExtraCAText = (mkGceHost "x86_64-linux" {
				extraModules = [ {
					cogworx.gce.controlCAPublicKey = gceBakeCAKey;
					cogworx.gce.extraTrustedUserCAKeys = [ gceBakeExtraCAKey ];
				} ];
			}).config.environment.etc."ssh/cogworx-control-ca.pub".text;
			# The realized sshd PAM stack, read as a string so gce-image-control-pam
			# can assert the ORDER of the account rules rather than their presence.
			gcePamSshd = gceCfg.security.pam.services.sshd.text;
		in lib.optionalAttrs ((mkHarnesses system pkgs) ? "hermes-agent") {
			# Exercise the same helper used by the container state unit. There is no
			# container boot harness in this repository, so retain one invocation check.
			container-state-unit = pkgs.runCommand "cogbox-container-state-unit" {} ''
				helper=${hermesHomeHelper}/bin/cogbox-hermes-home
				assert_fails() {
					if "$@"; then
						echo "expected failure: $*" >&2
						exit 1
					fi
				}

				mkdir fresh
				"$helper" "$PWD/fresh/persistent" "$PWD/fresh/home"
				test -d "$PWD/fresh/persistent"
				test "$(stat -c %a "$PWD/fresh/persistent")" = 700
				test -L "$PWD/fresh/home"
				test "$(readlink "$PWD/fresh/home")" = "$PWD/fresh/persistent"
				touch "$PWD/fresh/persistent/marker"
				"$helper" "$PWD/fresh/persistent" "$PWD/fresh/home"
				test -f "$PWD/fresh/persistent/marker"

				mkdir -p empty/persistent empty/home
				chmod 755 empty/persistent
				"$helper" "$PWD/empty/persistent" "$PWD/empty/home"
				test "$(stat -c %a "$PWD/empty/persistent")" = 700
				test "$(readlink "$PWD/empty/home")" = "$PWD/empty/persistent"

				mkdir -p nonempty/persistent nonempty/home
				touch nonempty/persistent/target-marker nonempty/home/source-marker
				assert_fails "$helper" "$PWD/nonempty/persistent" "$PWD/nonempty/home"
				test -f nonempty/persistent/target-marker
				test -f nonempty/home/source-marker
				test ! -L nonempty/home

				mkdir -p wrong-link/persistent wrong-link/elsewhere
				touch wrong-link/persistent/target-marker wrong-link/elsewhere/source-marker
				ln -s "$PWD/wrong-link/elsewhere" wrong-link/home
				assert_fails "$helper" "$PWD/wrong-link/persistent" "$PWD/wrong-link/home"
				test "$(readlink wrong-link/home)" = "$PWD/wrong-link/elsewhere"
				test -f wrong-link/persistent/target-marker
				test -f wrong-link/elsewhere/source-marker

				mkdir bad-target
				printf 'persistent marker\n' > bad-target/persistent
				assert_fails "$helper" "$PWD/bad-target/persistent" "$PWD/bad-target/home"
				grep -qFx 'persistent marker' bad-target/persistent
				test ! -e bad-target/home

				mkdir -p target-symlink/source
				touch target-symlink/source/marker
				ln -s "$PWD/target-symlink/source" target-symlink/persistent
				assert_fails "$helper" "$PWD/target-symlink/persistent" "$PWD/target-symlink/home"
				test "$(readlink target-symlink/persistent)" = "$PWD/target-symlink/source"
				test -f target-symlink/source/marker
				test ! -e target-symlink/home

				mkdir -p link-file/persistent
				touch link-file/persistent/target-marker
				printf 'link marker\n' > link-file/home
				assert_fails "$helper" "$PWD/link-file/persistent" "$PWD/link-file/home"
				test -f link-file/persistent/target-marker
				grep -qFx 'link marker' link-file/home

				mkdir identical
				assert_fails "$helper" "$PWD/identical/home" "$PWD/identical/home"
				test ! -e identical/home

				mkdir correct-missing
				ln -s "$PWD/correct-missing/persistent" correct-missing/home
				"$helper" "$PWD/correct-missing/persistent" "$PWD/correct-missing/home"
				test -d correct-missing/persistent
				test "$(readlink correct-missing/home)" = "$PWD/correct-missing/persistent"

				mkdir -p wrong-missing/source
				touch wrong-missing/source/marker
				ln -s "$PWD/wrong-missing/source" wrong-missing/home
				assert_fails "$helper" "$PWD/wrong-missing/persistent" "$PWD/wrong-missing/home"
				test ! -e wrong-missing/persistent
				test "$(readlink wrong-missing/home)" = "$PWD/wrong-missing/source"
				test -f wrong-missing/source/marker

				mkdir -p nonempty-missing/home
				printf 'source marker\n' > nonempty-missing/home/marker
				assert_fails "$helper" "$PWD/nonempty-missing/persistent" "$PWD/nonempty-missing/home"
				test ! -e nonempty-missing/persistent
				test -d nonempty-missing/home
				grep -qFx 'source marker' nonempty-missing/home/marker

				# Deterministically reproduce the post-validation race outcome: GNU ln
				# -T must reject the destination directory without creating a child link.
				mkdir -p raced/persistent raced/home
				touch raced/home/directory-marker
				assert_fails ln -sT -- "$PWD/raced/persistent" "$PWD/raced/home"
				test -d raced/home
				test -f raced/home/directory-marker
				test ! -e raced/home/persistent
				test "$(grep -c 'ln -sT --' "$helper")" = 2

				grep -qF '${hermesHomeHelper}/bin/cogbox-hermes-home /var/lib/cogbox-state/hermes-home /root/.hermes' ${containerStateScript}
				touch $out
			'';
		} // lib.optionalAttrs (builtins.hasAttr system inputs.llm-agents.packages) {
			# The harness's first-run dialog state is reconciled in TWO places -- the
			# container's claude-stub oneshot and the VM's brain-trust oneshot -- and,
			# inside the container one, on TWO branches (fresh write vs merge onto an
			# existing config). Nothing at eval time couples the three, so an edit can
			# fix one and leave a fresh sandbox parked on an interactive first-run
			# prompt instead of reaching the REPL. No unit or VM test in this repo
			# reaches that: it needs an interactive terminal, and `claude -p` passes
			# either way. Assert the realized scripts by grep: cheap,
			# and it fails on the drift rather than on the symptom.
			harness-firstrun-flags = pkgs.runCommand "cogbox-harness-firstrun-flags" { } ''
				fails=0
				container=${containerHarnessConfScript}
				vm=${vmHarnessConfScript}

				for flag in hasCompletedOnboarding bypassPermissionsModeAccepted; do
					# Container, fresh-write branch: the literal used when no config exists.
					if ! grep -qF "\"$flag\":true" "$container"; then
						echo "FAIL: container fresh write does not set $flag" >&2
						fails=$((fails + 1))
					fi
					# Container, merge branch: FORCED (=), not defaulted (//=), so a config
					# the harness has already rewritten still ends up with it.
					if ! grep -qF ".$flag = true" "$container"; then
						echo "FAIL: container merge branch does not force $flag" >&2
						fails=$((fails + 1))
					fi
					# VM: the same two, via brain-trust's isVm-guarded jq program.
					if ! grep -qF ".$flag = true" "$vm"; then
						echo "FAIL: VM brain-trust does not force $flag" >&2
						fails=$((fails + 1))
					fi
				done

				# bypassPermissionsModeAccepted is read off the GLOBAL config getter, so
				# it has to be top-level. Written under .projects[...] -- where the
				# neighbouring trust dialog legitimately lives -- it is never read, and
				# the dialog still fires with the config looking correct to a grep.
				if grep -qE 'projects\[[^]]*\]\.bypassPermissionsModeAccepted' "$container" "$vm"; then
					echo "FAIL: bypassPermissionsModeAccepted written under .projects[...]; the global getter would never see it" >&2
					fails=$((fails + 1))
				fi

				test "$fails" = 0
				touch $out
			'';

			harness-versions = pkgs.runCommand "cogbox-harness-versions" {} ''
				export HOME=$TMPDIR/home
				export HERMES_HOME=$HOME/.hermes
				mkdir -p "$HERMES_HOME"/{cron,sessions,logs,memories}
				assert_version() {
					expected=$1
					shift
					if ! output=$("$@" 2>&1); then
						printf 'version command failed: %s\n%s\n' "$*" "$output" >&2
						exit 1
					fi
					case "$output" in
					*"$expected"*) ;;
					*)
						printf 'expected version %s from %s, got: %s\n' "$expected" "$*" "$output" >&2
						exit 1
						;;
					esac
				}

				test '${releaseHarnesses.claude-code.version}' = '2.1.220'
				test '${releaseHarnesses.opencode.version}' = '1.18.7'
				test '${releaseHarnesses.codex.version}' = '0.145.0'
				test '${releaseHarnesses.hermes-agent.version}' = '2026.7.20'
				test '${releaseHarnesses.pi.version}' = '0.82.1'

				assert_version '2.1.220' ${releaseHarnesses.claude-code}/bin/claude --version
				assert_version '1.18.7' ${releaseHarnesses.opencode}/bin/opencode --version
				assert_version '0.145.0' ${releaseHarnesses.codex}/bin/codex --version
				assert_version '0.82.1' ${releaseHarnesses.pi}/bin/pi --version

				if ! hermes_output=$(${releaseHarnesses.hermes-agent}/bin/hermes --version 2>&1); then
					printf 'version command failed: hermes --version\n%s\n' "$hermes_output" >&2
					exit 1
				fi
				for expected in 'v0.19.0' '(2026.7.20)'; do
					case "$hermes_output" in
					*"$expected"*) ;;
					*)
						printf 'expected Hermes version %s, got: %s\n' "$expected" "$hermes_output" >&2
						exit 1
						;;
					esac
				done
				touch $out
			'';
		} // {
			# Pure-helper parity + credential-injection unit tests for the
			# mitmproxy L7 addon. Fast (no VM); keeps the addon's host
			# pattern / path / cred-injection logic honest on every build.
			addon-tests = pkgs.runCommand "cogbox-addon-tests" {
				nativeBuildInputs = [ pkgs.python3 ];
			} ''
				cp ${./l7-mitm-addon.py} l7-mitm-addon.py
				# The single-source stub-token / no-env-stub assertions read these
				# from ../ relative to tests/; stage them so the check can grep them.
				cp ${./cogbox-launch.sh} cogbox-launch.sh
				cp ${./flake.nix} flake.nix
				mkdir tests
				cp ${./tests/test_l7_addon.py} tests/test_l7_addon.py
				python3 tests/test_l7_addon.py
				touch $out
			'';

			# The launcher's `init` seeding and its failure-path hygiene, exercised
			# by RUNNING the script (no VM: every case stops at --init-only or fails
			# before the launch). Two invariants no unit test can reach: that
			# --no-implicit-dns / --self-addr actually reach config.json -- without a
			# producer the filter's parameterized port-53 allow and the l7proxy
			# self-address floor are dead code -- and that an init WITHOUT them
			# writes the pre-feature blob unchanged, which is what keeps the local
			# and k8s backends untouched. Plus: no failure path echoes credential
			# context, which matters wherever the launcher's stderr lands somewhere
			# retained outside the machine.
			launch-flag-tests = pkgs.runCommand "cogbox-launch-flag-tests" {
				nativeBuildInputs = with pkgs; [ bash jq coreutils gnugrep ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_launch_flags.sh} ${./cogbox-launch.sh}
				touch $out
			'';

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
			# On the container backend the guest half
			# (plugin commands/skills/agents + cogbox.packages) is
			# delivered by the cogbox-brain-materialize oneshot rebuilding the brain
			# at boot. That rebuild MUST evaluate the `-container` config: the VM
			# config imports microvm.nixosModules.microvm, whose input source cannot
			# be fetched in the fail-closed offline sandbox, so evaluating it aborts
			# and silently drops the whole guest half. This check (a) builds the
			# container brain from a fixture that ships a plugin command + package
			# and asserts both land in the brain, and (b) guards that the baked
			# boot rebuild targets the `-container` config, not the VM one.
			container-brain-command = pkgs.runCommand "cogbox-container-brain-command" { } ''
				brain=${self.nixosConfigurations.cogbox-x86_64-brain-fixture-container.config.system.build.cogboxBrain}
				# (a) a plugin-shipped command reaches the container brain's claude tree
				if [ ! -f "$brain/claude/commands/demo-rca.md" ]; then
					echo "FAIL: plugin command not in container brain: $brain/claude/commands/demo-rca.md" >&2
					ls -R "$brain/claude" >&2 || true
					exit 1
				fi
				# cogbox.packages reach the brain's $out/bin (the container PATH surface)
				if [ ! -e "$brain/bin/hello" ]; then
					echo "FAIL: cogbox.packages tool not in container brain: $brain/bin/hello" >&2
					exit 1
				fi
				# (b) the boot rebuild must target the `-container` config (no microvm)
				mat=${self.nixosConfigurations.cogbox-x86_64-container.config.systemd.services.cogbox-brain-materialize.serviceConfig.ExecStart}
				if ! grep -q 'cogbox-x86_64-container.config.system.build.cogboxBrain' "$mat"; then
					echo "FAIL: brain-materialize does not rebuild via the -container config" >&2
					exit 1
				fi
				if grep -qF 'cogbox-x86_64.config.system.build.cogboxBrain' "$mat"; then
					echo "FAIL: brain-materialize rebuilds via the VM config (microvm force-fetch regression)" >&2
					exit 1
				fi
				touch $out
			'';
			# GUEST-HALF DNS: no public fallback resolver, asserted against the
			# rendered resolved.conf rather than against prose.
			#
			# WHY THIS NEEDS A CHECK. The leak is invisible from inside the
			# guest's normal behaviour: resolution keeps working through the
			# link-scope server passt advertises, and only the GLOBAL scope
			# carries systemd's compiled-in 1.1.1.1/8.8.8.8/9.9.9.9 list -- so it
			# reads as `resolvectl status` trivia right up until a link-scope
			# failure ships an INTERNAL query name to a third-party resolver and
			# an internal-DNS outage comes back as an ordinary NXDOMAIN. It also
			# has a near-miss spelling: an empty LIST renders no line at all,
			# which is byte-identical to the defect, and only the empty STRING
			# renders the `FallbackDNS=` that overrides the compiled-in list.
			#
			# Written over "every guest config that renders the file" rather than
			# over the VM by name so that enabling resolved in the container later
			# is covered automatically instead of silently unasserted.
			guest-dns-no-public-fallback = pkgs.runCommand "cogbox-guest-dns-no-public-fallback" { } ''
				fails=0
				${lib.concatMapStrings ({ name, path }: ''
					conf=${path}
					if [ "$(grep -c '^FallbackDNS=' "$conf")" != 1 ]; then
						echo "FAIL: ${name}: resolved.conf carries $(grep -c '^FallbackDNS=' "$conf") FallbackDNS lines, expected exactly 1; with none, systemd's compiled-in PUBLIC resolver list stands at global scope and an internal query name leaks the moment link-scope DNS is unset or fails" >&2
						fails=$((fails + 1))
					elif ! grep -qx 'FallbackDNS=' "$conf"; then
						echo "FAIL: ${name}: FallbackDNS names a resolver ($(grep '^FallbackDNS=' "$conf")); the guest must resolve exactly what the host resolves, or fail visibly" >&2
						fails=$((fails + 1))
					fi
				'') guestResolvedConfs}
				# Non-vacuity. The microVM guest enables networkd, which
				# default-enables resolved, so that config MUST have contributed a
				# file to the loop above; if the attribute path ever moves, this
				# check would otherwise pass by asserting nothing.
				${lib.optionalString (!(lib.any (c: c.name == configName system) guestResolvedConfs)) ''
					echo "FAIL: ${configName system} renders no /etc/systemd/resolved.conf, so this check asserted nothing about the guest's resolver" >&2
					fails=$((fails + 1))
				''}
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';
			cogbox-vm = pkgs.testers.runNixOSTest (import ./tests/cogbox.nix {
				inherit self pkgs system;
			});
			# Standing bypass-test suite for the container-mode nft egress floor
			# (TODO): loads the real cogbox-nft-divert.sh and probes every
			# egress path to PROVE the DNS-tunnel / ICMP / non-tcp-udp-L4 leaks are
			# closed. Needs nested KVM -- runs in CI / on a KVM host, not the dev box.
			nft-floor-bypass = pkgs.testers.runNixOSTest (import ./tests/nft-floor-bypass.nix {
				inherit self pkgs;
			});
		} // lib.optionalAttrs (system == "x86_64-linux") {
			# --- GCE backend image checks -------------------------------------
			#
			# The image itself is an operator bake. What the gce-image-* checks
			# assert is the thing the bake cannot change: the CLOSURE and the UNIT
			# GRAPH of the system inside it. Every one of them stands in for a
			# failure that is invisible until a real instance is already broken in
			# the field.

			# THE offline-boot regression, caught at build time. cogbox-launch.sh's
			# custom-flake re-exec EVALUATES the VM config, which forces every
			# flake input SOURCE TREE. A non-resident input aborts the eval and
			# silently drops the whole guest half.
			# google-compute-image.nix does not thread `additionalPaths` through to
			# make-disk-image.nix, so system.extraDependencies is the only route
			# into the registered store, and this check is what proves it took.
			gce-image-offline-closure = pkgs.runCommand "gce-image-offline-closure" { } ''
				fails=0
				for src in \
					'${inputs.microvm}' \
					'${inputs.llm-agents}' \
					'${inputs.nix-mcp}' \
					'${inputs.illustris-lib}'; do
					if ! grep -qxF "$src" ${gceClosure}/store-paths; then
						echo "FAIL: flake input source $src is NOT in the GCE image's registered closure;" >&2
						echo "      the launcher's re-exec will abort offline and drop the guest half" >&2
						fails=$((fails + 1))
					fi
				done
				# The cogbox package itself, and with it the microvm runner and the
				# guest kernel/initrd/toplevel, must be resident too.
				if ! grep -q 'cogbox' ${gceClosure}/store-paths; then
					echo "FAIL: no cogbox path in the GCE image closure" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# What a flake FETCH needs from the image's userland, which is not the
			# same question as what its closure contains. nix's git+http(s)/ssh
			# fetcher execs the `git` CLI off PATH. Without git, every curated
			# catalog entry fails at resolve time, including entries handled by
			# an ephemeral resolver VM.
			#
			# Neither half is REFERENCED by anything in the image -- the caller is
			# nix, at runtime, by name -- so nothing but this check stands between
			# a boot-disk closure trim and a backend that cannot install a plugin.
			gce-image-flake-fetch = pkgs.runCommand "gce-image-flake-fetch" { } ''
				fails=0
				# On the system path, not merely in the closure: nix resolves the
				# fetcher off PATH, and /run/current-system/sw/bin (= sw/bin of the
				# toplevel) is what a control-channel exec, the supervisor unit and
				# a serial break-glass session all share. Do NOT weaken this to a
				# closureInfo store-paths grep the way the offline-closure check
				# above does -- git was ALREADY in the broken image's closure (the
				# guest half pulls it in), so a closure grep passed while the whole
				# catalog was uninstallable. Adding it here costs ~68 KiB of
				# system-path symlinks, not a git closure.
				if [ ! -x ${gceToplevel}/sw/bin/git ]; then
					echo "FAIL: no git on /run/current-system/sw/bin; nix's git+http(s)/ssh flake fetcher execs the git CLI, so every git+ plugin URL dies with 'executing git: No such file or directory' -- and every curated catalog entry is a git+ URL" >&2
					fails=$((fails + 1))
				fi
				# TLS trust for the https variant. The pod image needs pkgs.cacert +
				# SSL_CERT_FILE for this because it is a bare userland; on NixOS it
				# comes from security.pki instead, i.e. from a file that can vanish
				# by REMOVAL (an environment.etc mkForce, a stripped security.pki)
				# with no missing package to notice. The failure mode is then a
				# certificate error on git+https rather than a missing binary.
				if [ ! -e ${gceToplevel}/etc/ssl/certs/ca-certificates.crt ]; then
					echo "FAIL: the realized system has no /etc/ssl/certs/ca-certificates.crt; git's curl would have no CA bundle, so a git+https plugin fetch cannot verify TLS" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The lifecycle credential's setMetadata capability is inert rather
			# than pretending the permission is narrow. Two of the three doors are
			# closed here: startup/shutdown script execution and OS Login key
			# management. A nixpkgs bump that re-enables either would silently hand
			# `instances.setMetadata` root on the trusted half again.
			gce-image-guest-agent-disabled = pkgs.runCommand "gce-image-guest-agent-disabled" { } ''
				fails=0
				for u in google-guest-agent google-startup-scripts google-shutdown-scripts; do
					hits=$(find ${gceUnits} -name "$u.service" -path '*.wants/*' 2>/dev/null || true)
					if [ -n "$hits" ]; then
						echo "FAIL: $u is still wanted by a target:" >&2
						echo "$hits" >&2
						fails=$((fails + 1))
					fi
					# A .wants symlink is only one of the two routes in. A
					# Wants=/Requires= inside some other unit would start it
					# just as effectively and leaves no symlink to find.
					pulls=$(grep -rlE "^(Wants|Requires|Requisite|BindsTo)=.*$u" ${gceUnits} 2>/dev/null || true)
					if [ -n "$pulls" ]; then
						echo "FAIL: a unit pulls in $u by dependency:" >&2
						echo "$pulls" >&2
						fails=$((fails + 1))
					fi
				done
				if [ '${lib.boolToString gceCfg.security.googleOsLogin.enable}' != false ]; then
					echo "FAIL: security.googleOsLogin.enable is on; metadata ssh-keys would grant login" >&2
					fails=$((fails + 1))
				fi
				# The OS Login PAM/NSS half leaves its own traces even when the
				# service is not wanted, so assert the realized sshd config too.
				if grep -qi 'oslogin' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd_config still references OS Login" >&2
					fails=$((fails + 1))
				fi
				# Certificate-only control auth: a bare public key must be
				# refused, so there is no authorized_keys path at all.
				if ! grep -qx 'AuthorizedKeysFile none' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd still has an AuthorizedKeysFile path; a bare public key would be accepted" >&2
					fails=$((fails + 1))
				fi
				if ! grep -q '^TrustedUserCAKeys ' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd has no TrustedUserCAKeys; the control CA is not baked in" >&2
					fails=$((fails + 1))
				fi
				# The VM host key must live on the STATE disk, or Stop and a
				# boot-disk swap regenerate it and force a silent re-TOFU.
				if ! grep -q '^HostKey /var/lib/cogbox-state/' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd's HostKey is not on the state disk" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# Floor-before-sandbox and scrub-independence are both load-bearing
			# orderings. Both are the kind of thing a later "tidy the
			# dependency graph" commit breaks without any test noticing.
			gce-image-unit-ordering = pkgs.runCommand "gce-image-unit-ordering" { } ''
				fails=0
				sup=${gceUnits}/cogworx-supervisor.service
				scrub=${gceUnits}/cogworx-attr-scrub.service
				floor=${gceUnits}/cogworx-floor.service

				# Requires=, not merely After=. With After= alone a floor-failed boot
				# still starts the sandbox, and a full-mode guest on a floorless VM
				# can forge the very guest attributes the boot path trusts.
				req=$(grep '^Requires=' "$sup" || true)
				case "$req" in
					*cogworx-attr-scrub.service*) ;;
					*) echo "FAIL: supervisor does not Requires= the scrub unit ($req)" >&2; fails=$((fails + 1)) ;;
				esac
				case "$req" in
					*cogworx-floor.service*) ;;
					*) echo "FAIL: supervisor does not Requires= the floor unit ($req)" >&2; fails=$((fails + 1)) ;;
				esac
				aft=$(grep '^After=' "$sup" || true)
				case "$aft" in
					*'var-lib-cogbox\x2dstate.mount'*) ;;
					*) echo "FAIL: supervisor is not After= the state-disk mount ($aft)" >&2; fails=$((fails + 1)) ;;
				esac
				if ! grep -q '^ExecStopPost=.' "$sup"; then
					echo "FAIL: supervisor has no ExecStopPost; readiness would latch across the crash paths the poll loop cannot see" >&2
					fails=$((fails + 1))
				fi

				# The scrub retries forever and is INDEPENDENT of the floor. A scrub
				# sequenced after the floor check would never run on a floor-failed
				# same-epoch reboot -- exactly the boot whose stale attribute still
				# carries the current nonce.
				if ! grep -qx 'StartLimitIntervalSec=0' "$scrub"; then
					echo "FAIL: the scrub unit has a start limit; a failed scrub would become terminal" >&2
					fails=$((fails + 1))
				fi
				if grep -E '^(After|Requires|Wants|BindsTo|PartOf)=' "$scrub" | grep -q 'cogworx-floor'; then
					echo "FAIL: the scrub unit is ordered on the floor unit; the same-epoch stale attribute would survive" >&2
					fails=$((fails + 1))
				fi

				# RestartMode=direct, not a nicety. Under the default the unit
				# transits through failed on its way into auto-restart, which
				# CANCELS the supervisor's start job for the rest of the boot --
				# so one transient scrub failure permanently strands the instance
				# in Booting while the scrub itself succeeds on retry #2.
				if ! grep -qx 'RestartMode=direct' "$scrub"; then
					echo "FAIL: the scrub unit is not RestartMode=direct; its first transient failure would cancel the supervisor's start job for the whole boot" >&2
					fails=$((fails + 1))
				fi

				# The floor's live probes, and the empty-set fail-closed that
				# stops a VACUOUS rule 2 from passing a shape-only check.
				if ! grep -q '^ExecStartPost=.' "$floor"; then
					echo "FAIL: the floor unit has no ExecStartPost; the ruleset would be installed but never verified" >&2
					fails=$((fails + 1))
				fi

				# THE FIRST-BOOT SOURCE. cogworx-self-addrs is stamped EMPTY into
				# every insert body (no address exists yet), so a floor unit with
				# only that source refuses the boot of every freshly created
				# sandbox and of every resolver VM -- neither of which gets a
				# second chance to be repaired by a later Start. The install leg
				# must therefore fall back to the metadata server's own interface
				# addresses, and only an empty set from BOTH may fail the boot.
				install=${gceFloorInstall}
				if ! grep -qF 'network-interfaces' "$install"; then
					echo "FAIL: the floor installer has no metadata-server fallback for cogworx-self-addrs; a first boot (empty attribute) would fail closed forever" >&2
					fails=$((fails + 1))
				fi
				# RULE 2 IS A skuid RANGE OVER EVERY UID, SCOPED TO THE ORIGINAL
				# DIRECTION OF A FLOW, and all three of those are load-bearing.
				#
				# It must carry a skuid EXPRESSION: a drop written as a bare `ip
				# daddr <self> drop` also matches the KERNEL-GENERATED return
				# packets of a same-host flow (the RST when nothing is listening),
				# which carry the VM's own address as their destination and no
				# owning socket at all -- so they can never match the skuid-scoped
				# control-uid accept above and get swallowed by the drop below it.
				#
				# It must NOT be narrowed to named uids to get that property. An
				# enumeration (`skuid cogbox-passt`, `skuid cogbox-proxy`) has a
				# skuid expression and would pass the first half while leaving
				# root-run and `nixbld*` in-VM plugin builds -- and passt's own
				# pre-drop, root-owned listening sockets -- outside rule 2. A range
				# is a skuid expression AND covers every uid, so it satisfies both;
				# 4294967295 is (uid_t)-1 and never a real account.
				#
				# And it must be scoped to `ct direction original`, because the
				# skuid range does NOT cover the return path once something is
				# actually LISTENING. passt creates its port-forward listener
				# BEFORE its privilege drop, so a real SYN-ACK has a real owning
				# socket (fsuid 0), no NFT_BREAK happens, and its destination port
				# is the CLIENT's ephemeral port -- unmatchable by any dport accept.
				# The range deny would take cogbox ssh, Terminal,
				# Console-over-ssh and the user SSH gateway down. Direction rather
				# than `ct state new`: a
				# state-scoped deny would additionally let a flow that survived a
				# floor reload keep running, which the stateless rule did not.
				#
				# tests/test_floor.sh proves all of it on the RENDERED ruleset and,
				# in its live section, against a REAL listener in a throwaway netns;
				# these lines stop the format string itself from regressing.
				if ! grep -qF 'meta skuid 0-4294967294 ct direction original ip daddr %s counter drop comment "cogworx-floor-rule2-self"' "$install"; then
					echo "FAIL: the floor installer's rule-2 deny is not the every-uid, original-direction range; it has either lost its skuid match, been narrowed to named uids, or lost the direction scoping that keeps a real listener's reply out of the drop" >&2
					fails=$((fails + 1))
				fi
				if grep -F 'cogworx-floor-rule2-self' "$install" | grep -qF 'meta skuid "'; then
					echo "FAIL: the floor installer renders a named-uid rule-2 deny; root-run and nixbld* plugin builds and passt's pre-drop sockets would be outside rule 2" >&2
					fails=$((fails + 1))
				fi
				# RULE 3 IS THE LOOPBACK LEG, AND IT IS THE OPPOSITE SHAPE TO RULE
				# 2 ON PURPOSE.
				#
				# Rule 2 covers the VM's own non-loopback addresses from every uid.
				# It cannot cover loopback: the L7 remap funnel is a shim-side
				# connect() rewrite to 127.0.0.1:<l7base> made by passt itself, and
				# the trusted half's own components talk to each other there
				# (l7proxy -> the mitm hop, mitmproxy -> its upstreams, the nix
				# daemon, sshd). So loopback was left out of the floor entirely,
				# and the property "a guest cannot address the enclosing VM's
				# services" rested on passt alone: it drops tap frames carrying a
				# loopback address (tap.c), and --no-map-gw removes the
				# gateway->127.0.0.1 mapping. Both are upstream behaviors, so an
				# independent floor remains necessary.
				#
				# Rule 3 supplies the missing layer: the passt uid, and only the
				# passt uid, may not OPEN a flow to loopback except to the funnel's
				# own targets. A skuid RANGE here would cut the trusted half's own
				# loopback traffic, so this is the one rule that must stay
				# uid-scoped -- the exact opposite of rule 2, and worth stating so
				# a later reader does not "fix" the asymmetry.
				if ! grep -qF 'ip daddr 127.0.0.0/8 counter drop comment "cogworx-floor-rule3-loopback"' "$install"; then
					echo "FAIL: the floor installer renders no rule-3 loopback deny; the guest-to-loopback path would rest on passt's tap filter alone, with nothing in the floor behind it" >&2
					fails=$((fails + 1))
				fi
				if ! grep -F 'cogworx-floor-rule3-loopback' "$install" | grep -qF 'ct direction original'; then
					echo "FAIL: the floor installer's rule-3 deny is not scoped to the original direction; it would swallow the L7 funnel's own SYN-ACK (daddr 127.0.0.1, client ephemeral port) and take L7 down the way the stateless rule-2 deny took cogbox ssh down" >&2
					fails=$((fails + 1))
				fi
				if grep -F 'cogworx-floor-rule3-loopback' "$install" | grep -qF 'meta skuid 0-4294967294'; then
					echo "FAIL: the floor installer's rule-3 deny covers every uid; l7proxy, mitmproxy, the nix daemon and sshd all talk over this machine's loopback" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'cogworx-floor-rule3-l7-funnel' "$install"; then
					echo "FAIL: the floor installer renders no rule-3 funnel exception; the L7 remap funnel connects to 127.0.0.1:<l7base> under the passt uid and would be dropped by the rule above" >&2
					fails=$((fails + 1))
				fi
				# RULE 3'S SECOND AND LAST EXCEPTION: the VM's own DNS forwarder.
				# It is there because guest/host resolution parity has no shape
				# that leaves rule 1 alone -- passt re-emits the guest's
				# intercepted DNS queries under the PASST uid, so a forwarding
				# target of 169.254.169.254 is indistinguishable at nftables from
				# the guest dialling the metadata API and rule 1 drops it
				# (measured). Sending them to a root-run loopback forwarder moves
				# that hop to a uid rule 1 does not name.
				#
				# THE CAP is the assertion that matters, not the presence: rule 3's
				# accept set must be the funnel ports plus THIS ONE SOCKET, and the
				# widening that would pass every other check here is a second
				# accept line. Two accepts (udp + tcp) and two denies (v4 + v6) on
				# top of the funnel accept is five rule-3 lines, exactly.
				if ! grep -qF 'cogworx-floor-rule3-dns-forwarder' "$install"; then
					echo "FAIL: the floor installer renders no rule-3 DNS-forwarder exception; passt's re-emitted guest DNS query is a loopback connect under the passt uid, so every sandbox on the VM would resolve nothing" >&2
					fails=$((fails + 1))
				fi
				if [ "$(grep -cF 'cogworx-floor-rule3' "$install")" != 5 ]; then
					echo "FAIL: the floor installer renders $(grep -cF 'cogworx-floor-rule3' "$install") rule-3 lines, expected 5 (funnel accept, DNS-forwarder udp+tcp accepts, v4 and v6 loopback denies); an added accept widens the passt uid's loopback reach" >&2
					fails=$((fails + 1))
				fi
				if grep -F 'cogworx-floor-rule3-dns-forwarder' "$install" | grep -qE 'dport [^ ]*[-{]'; then
					echo "FAIL: the rule-3 DNS-forwarder exception carries a port range or set; it must name exactly one port, or it re-admits neighbouring loopback listeners" >&2
					fails=$((fails + 1))
				fi
				verify=${gceFloorVerify}
				for token in cogbox-passt cogbox-proxy 169.254.169.254 \
					'rule 1, metadata API' 'rule 2, passt leg' 'rule 2, proxy leg' \
					'rule 2 control-uid exception' 'Refusing the boot' \
					'expected blocked' 'expected connected or refused' \
					'rule 2 exempt-port return path' 'systemd-socket-activate' \
					'rule 3, loopback leg' 'rule 3 L7 funnel exception' \
					'rule 3 host DNS forwarder exception'; do
					if ! grep -qF "$token" "$verify"; then
						echo "FAIL: the floor verifier does not mention '$token'" >&2
						fails=$((fails + 1))
					fi
				done

				# PROBE POLARITY, and the one probe that is exempt from it. The
				# control-uid EXCEPTION probe is proven healthy by "connected OR
				# refused" and broken only by a DROP, because this unit runs before
				# the supervisor that starts passt, so nothing can be listening on
				# the guest SSH forward when the probe runs and a correct VM answers
				# RST. Demanding a completed connection there would fail every boot
				# of a correct image -- and the obvious remedy for that is to widen
				# rule 2, which is the pressure the probe exists to resist.
				#
				# The RETURN-PATH probe demands "open" and is allowed to, because it
				# binds its own root-owned listener on an exempt port first. That
				# distinction matters: an
				# empty port answers with a socket-less RST that breaks past the
				# deny, so the exception probe reads healthy under a deny that eats
				# every real reply. Deleting the return-path probe puts the image
				# back in the state where nothing on the VM can see that bug.
				if grep -qF 'expected reachable' "$verify"; then
					echo "FAIL: the floor verifier still demands a reachable control-uid connect; nothing can listen on the guest SSH forward before the supervisor starts passt" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'expected open' "$verify"; then
					echo "FAIL: the floor verifier no longer asserts a COMPLETED connection against its own listener on an exempt port; the same-host return path would be unverifiable before a sandbox starts" >&2
					fails=$((fails + 1))
				fi

				# The in-VM store GC. "NixGCReconciler is unsupported" is a
				# statement about the control plane; the boot disk still fills.
				for u in cogworx-nix-gc.service cogworx-nix-gc.timer; do
					if [ ! -e ${gceUnits}/$u ]; then
						echo "FAIL: $u is missing" >&2
						fails=$((fails + 1))
					fi
				done

				# The resolver VM's in-VM self-destruct belt.
				if [ ! -e ${gceUnits}/cogworx-resolver-deadline.service ]; then
					echo "FAIL: cogworx-resolver-deadline.service is missing" >&2
					fails=$((fails + 1))
				fi
				# ... and the belt's own FAIL-OPEN, which presence cannot see. The
				# arm script decides "not a resolver boot" from a failed metadata
				# read, and that verdict is `exit 0` under RemainAfterExit=true --
				# a LATCH: Restart=on-failure never fires and the deadline never
				# arms for the rest of the boot. So an unreachable endpoint must be
				# a RETRY, never a verdict, and the only way to tell the two apart
				# is to probe reachability first (the shape cogworx-attr-scrub
				# already uses) before reading the flag. This is a static shape
				# assertion because the unit has no executable test home: it takes
				# no COGWORX_MD_BASE override, so unlike the floor and supervisor
				# scripts it cannot be run against a file:// metadata tree.
				arm=${gceResolverDeadlineScript}
				if ! grep -qF 'instance/id' "$arm"; then
					echo "FAIL: the resolver-deadline arm script does not probe metadata reachability before reading the cogworx-resolver flag; an unreachable endpoint would read as 'not a resolver boot' and latch an UNARMED self-destruct on a VM that evaluates attacker-controlled flakes" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'will retry' "$arm"; then
					echo "FAIL: the resolver-deadline arm script has no retry path; every metadata failure would exit 0 and latch an unarmed deadline" >&2
					fails=$((fails + 1))
				fi
				# The retry path must come BEFORE the flag read, or it is not the
				# thing standing between an unreachable endpoint and the latch.
				if [ "$(grep -n 'instance/id' "$arm" | head -n1 | cut -d: -f1)" -ge "$(grep -n 'attributes/cogworx-resolver' "$arm" | head -n1 | cut -d: -f1)" ]; then
					echo "FAIL: the resolver-deadline arm script reads the cogworx-resolver flag before probing reachability; the unreachable case would still latch" >&2
					fails=$((fails + 1))
				fi

				# A non-interactive `ssh <vm> cogbox <verb>` sources no profile, so
				# without these three baked into the program itself every control
				# verb exits 66. NAME-presence only: it says nothing about whether the
				# wrapper can win against a value PAM already set, which is a separate
				# and equally fatal failure -- see gce-cogbox-wrapper-env.
				for v in XDG_CONFIG_HOME COGBOX_DATA XDG_RUNTIME_DIR; do
					if ! grep -qF "$v" ${gceCogboxWrapper}/bin/cogbox; then
						echo "FAIL: the cogbox wrapper does not set $v; control-channel verbs would exit 66" >&2
						fails=$((fails + 1))
					fi
				done

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The filesystem every other path assumed and nothing created. The mkfs
			# guard is the load-bearing half: an unconditional mkfs on a resumed
			# instance destroys the L7 CA private key, the secret store and the VM
			# host key on every Start.
			gce-image-state-disk-ordering = pkgs.runCommand "gce-image-state-disk-ordering" { } ''
				fails=0
				fstab=${gceToplevel}/etc/fstab
				line=$(grep ' /var/lib/cogbox-state ' "$fstab" || true)
				if [ -z "$line" ]; then
					echo "FAIL: no /var/lib/cogbox-state entry in the realized fstab" >&2
					fails=$((fails + 1))
				fi
				case "$line" in
					'/dev/disk/by-id/google-cogworx-state '*) ;;
					*) echo "FAIL: the state disk is not resolved through its fixed by-id deviceName: $line" >&2; fails=$((fails + 1)) ;;
				esac
				# sshd-keygen is what actually writes the host key, so ordering only
				# sshd would still lose the race that regenerates it on the boot disk.
				for dep in sshd-keygen.service sshd.service cogworx-supervisor.service cogworx-attr-scrub.service; do
					case "$line" in
						*"x-systemd.before=$dep"*) ;;
						*) echo "FAIL: the state mount is not ordered before $dep: $line" >&2; fails=$((fails + 1)) ;;
					esac
				done
				mkfs=${gceStateDiskScript}
				if ! grep -qF 'blkid' "$mkfs"; then
					echo "FAIL: the mkfs leg has no blkid guard; a resume would reformat the state disk" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'mkfs.ext4' "$mkfs"; then
					echo "FAIL: the state-disk unit never formats anything" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# Serial classification. On GCE `console` is ttyS0, the port
			# Backend.Log reads: provider-retained state outside the VM boundary,
			# readable under a coarser grant than the control channel. cogbox.log
			# carries l7proxy's per-request decisions and the mitmproxy
			# credential-injection addon's output, so it must never land there.
			#
			# Scoped to the cogworx-* units this repository ships. The upstream
			# getty/emergency/rescue units legitimately own a tty and carry no
			# cogbox state; asserting over them would pin unrelated nixpkgs
			# internals and say nothing about this invariant.
			gce-image-serial-classes = pkgs.runCommand "gce-image-serial-classes" { } ''
				fails=0
				for u in ${gceUnits}/cogworx-*.service ${gceUnits}/cogworx-*.timer; do
					[ -f "$u" ] || continue
					if grep -E '^Standard(Output|Error)=' "$u" | grep -Eq 'console|tty'; then
						echo "FAIL: $(basename "$u") sends a standard stream to console/tty:" >&2
						grep -E '^Standard(Output|Error)=' "$u" >&2
						fails=$((fails + 1))
					fi
				done
				sup=${gceUnits}/cogworx-supervisor.service
				if ! grep -qx 'StandardOutput=journal' "$sup"; then
					echo "FAIL: the supervisor is not StandardOutput=journal (journal+console would export the whole runtime log to serial)" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'StandardError=journal' "$sup"; then
					echo "FAIL: the supervisor is not StandardError=journal" >&2
					fails=$((fails + 1))
				fi
				# The tail leg exists, but in its own journal-only unit.
				script=${gceSuperviseScript}
				if grep -v '^[[:space:]]*#' "$script" | grep -q 'cogbox\.log'; then
					echo "FAIL: the supervisor script touches cogbox.log; that leg belongs in cogworx-cogbox-log.service" >&2
					fails=$((fails + 1))
				fi
				logunit=${gceUnits}/cogworx-cogbox-log.service
				if [ ! -e "$logunit" ]; then
					echo "FAIL: cogworx-cogbox-log.service is missing; the runtime log has nowhere to go" >&2
					fails=$((fails + 1))
				elif ! grep -qx 'StandardOutput=journal' "$logunit"; then
					echo "FAIL: cogworx-cogbox-log.service is not journal-only" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The substituter posture, as an assertion rather than prose. In-VM
			# plugin builds process attacker-controlled flakes, so an unsigned
			# substituter here is a cross-instance code-injection path.
			# GUEST/HOST RESOLUTION PARITY, asserted against the realized image.
			#
			# THE PROPERTY. A cogbox guest must resolve names the way the host
			# does, so an internal name resolves to its internal address -- what
			# the local, k8s and container backends get for free because the guest
			# inherits the host's resolver. Here it cannot: at the default
			# `vpcResolver` the host's upstream IS the metadata address, and floor
			# rule 1 denies the passt uid the whole of 169.254.0.0/16 in every
			# mode. The first shape of this backend therefore advertised a PUBLIC
			# resolver to the guest, which answers internal names publicly or not
			# at all.
			#
			# THE MECHANISM, and why every leg below is load-bearing. passt is told
			# to INTERCEPT the guest's queries (`--dns-forward`) and re-emit them
			# to a loopback forwarder on the host (`--dns-host`), which is
			# systemd-resolved's stub. But passt substitutes the --dns-forward
			# address into its DHCP offer only when the nameserver it reads from
			# /etc/resolv.conf is a LOOPBACK one (conf.c add_dns_resolv4). So:
			# resolved must be enabled, resolv.conf must point at its stub,
			# resolved's upstream must be the one `vpcResolver` names, and the units
			# that depend on it must be ordered after it. Miss any one and the guest is
			# handed the host's real resolver, rule 1 drops every query, and the
			# sandbox comes up healthy resolving NOTHING -- precisely the failure
			# mode nothing else in this flake can see.
			gce-image-guest-dns = pkgs.runCommand "gce-image-guest-dns" { } ''
				fails=0
				# 1. The forwarder exists and /etc/resolv.conf names it. This is
				#    the leg that makes passt advertise the forward address at all.
				rc=${gceToplevel}/etc/resolv.conf
				if [ ! -L "$rc" ]; then
					echo "FAIL: /etc/resolv.conf is not the systemd-resolved stub symlink; passt would read the host's real resolver and advertise IT to the guest" >&2
					fails=$((fails + 1))
				elif [ "$(readlink "$rc")" != /run/systemd/resolve/stub-resolv.conf ]; then
					echo "FAIL: /etc/resolv.conf points at $(readlink "$rc"), not resolved's stub" >&2
					fails=$((fails + 1))
				fi
				if [ ! -e ${gceUnits}/systemd-resolved.service ] && [ ! -e ${gceUnits}/sysinit.target.wants/systemd-resolved.service ]; then
					echo "FAIL: systemd-resolved is not enabled; nothing binds the loopback socket passt forwards guest DNS to" >&2
					fails=$((fails + 1))
				fi
				# 2. Its upstream is the one `vpcResolver` names -- the VPC resolver
				#    by default, or another full recursive resolver -- and it is
				#    authoritative for every name. A resolved
				#    that fell back to a public resolver would reproduce the exact
				#    defect this replaced, quietly.
				conf=${gceToplevel}/etc/systemd/resolved.conf
				if ! grep -qx 'DNS=${gceCfg.cogworx.gce.vpcResolver}' "$conf"; then
					echo "FAIL: resolved's upstream is not cogworx.gce.vpcResolver (${gceCfg.cogworx.gce.vpcResolver}); the guest and host would not resolve the same names, and internal names would not resolve internally" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'Domains=~.' "$conf"; then
					echo "FAIL: resolved's pinned upstream is not authoritative for all names (no 'Domains=~.'); some lookups would take another route" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'FallbackDNS=' "$conf"; then
					echo "FAIL: FallbackDNS is not explicitly empty; systemd's compiled-in PUBLIC resolver list would stand behind the configured upstream" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'DNSStubListener=true' "$conf"; then
					echo "FAIL: resolved's stub listener is off; the address passt forwards to would bind nothing" >&2
					fails=$((fails + 1))
				fi
				# 3. The supervisor hands cogbox BOTH halves and the dependent
				#    units are ordered after the forwarder. Ordering is not
				#    cosmetic: before resolved is up /etc/resolv.conf is a DANGLING
				#    symlink and passt advertises no resolver at all, and the
				#    floor's probe 8 connects to the stub.
				sup=${gceUnits}/cogworx-supervisor.service
				if ! grep -q 'COGBOX_HOST_RESOLVER=${gceCfg.cogworx.gce.hostResolver}' "$sup"; then
					echo "FAIL: the supervisor unit does not carry COGBOX_HOST_RESOLVER=${gceCfg.cogworx.gce.hostResolver}; passt would have no pinned forwarding target and cogbox init no --dns-host seed" >&2
					fails=$((fails + 1))
				fi
				for u in ${gceUnits}/cogworx-supervisor.service ${gceUnits}/cogworx-floor.service; do
					if ! grep -q '^After=.*systemd-resolved.service' "$u"; then
						echo "FAIL: $u is not ordered after systemd-resolved.service" >&2
						fails=$((fails + 1))
					fi
				done
				# 4. The supervisor script's own two legs: the --dns-host seed that
				#    keeps the L4 shim from dropping passt's re-emitted query, and
				#    the refusal when resolv.conf does not name the forwarder.
				sh=${gceSuperviseScript}
				if ! grep -qF -- '--dns-host' "$sh"; then
					echo "FAIL: the supervisor does not pass --dns-host to cogbox init; the L4 shim's loopback deny would eat passt's re-emitted guest DNS query and every rules-mode sandbox would resolve nothing" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'RESOLV_CONF' "$sh"; then
					echo "FAIL: the supervisor never checks that resolv.conf names the forwarder; passt would silently advertise the host's real resolver to the guest" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# THE BOOT PATH MUST NOT DEPEND ON DNS, asserted because nothing else
			# can see it. Every leg of the boot/control path names the metadata
			# server by NAME -- the supervisor's readiness write and
			# cogworx-instance read, the control-cert principal fetch, the floor's
			# first-boot self-address fallback, the scrub, the resolver
			# self-destruct belt, supervise.sh's MD base, and
			# google-compute-config.nix's networking.timeServers -- while the only
			# resolver any of them can reach is the SINGLE upstream `vpcResolver`
			# names, which `Domains=~.` makes authoritative for every name with an
			# empty FallbackDNS behind it.
			#
			# The /etc/hosts pin keeps metadata access independent of the
			# configured resolver. This check asserts the realized file because
			# several boot units depend on that property.
			gce-image-metadata-pin = pkgs.runCommand "gce-image-metadata-pin" { } ''
				fails=0
				hosts=${gceToplevel}/etc/hosts
				# The pin itself, asserted on the REALIZED file rather than on the
				# option that wrote it: this image sets networking.hosts and
				# google-compute-config.nix independently ships the same mapping
				# through networking.extraHosts, so what matters is that at least
				# one of them still lands in /etc/hosts.
				if ! grep -E '^[[:space:]]*169\.254\.169\.254[[:space:]]' "$hosts" | grep -qE '(^|[[:space:]])metadata\.google\.internal([[:space:]]|$)'; then
					echo "FAIL: /etc/hosts does not pin metadata.google.internal to 169.254.169.254; metadata access would depend on the configured resolver" >&2
					fails=$((fails + 1))
				fi
				# `metadata` is the short alias google-compute-config.nix also
				# ships; nothing here uses it, but a pin that names only one of the
				# two would be a surprise for an operator debugging by hand.
				if ! grep -E '^[[:space:]]*169\.254\.169\.254[[:space:]]' "$hosts" | grep -qE '(^|[[:space:]])metadata([[:space:]]|$)'; then
					echo "FAIL: /etc/hosts pins metadata.google.internal but not the short 'metadata' alias" >&2
					fails=$((fails + 1))
				fi
				# OUR OWN CONTRIBUTION, asserted separately, and the realized-file
				# legs above are exactly why it has to be: they pass on either
				# source, so deleting this module's `networking.hosts` line stays
				# green on google-compute-config.nix's extraHosts alone. That is the
				# invariant the duplication exists for -- inheriting a boot-critical
				# mapping from another module's default is how it vanishes in a
				# nixpkgs bump -- and it is invisible to a check that only reads the
				# merged output. Same asymmetry gce-image-control-pam closes with an
				# order comparison: the property that matters is not fully
				# observable in the artifact, so assert the source too. Both legs
				# stay: this one alone would pass an image whose /etc/hosts was
				# emptied downstream.
				pinned='${lib.concatStringsSep " " (gceCfg.networking.hosts."169.254.169.254" or [ ])}'
				for name in metadata.google.internal metadata; do
					case " $pinned " in
						*" $name "*) ;;
						*) echo "FAIL: this module's own networking.hosts no longer pins '$name' to 169.254.169.254 (it carries: $pinned); the realized /etc/hosts would then rest entirely on google-compute-config.nix's extraHosts default, which is not ours to rely on" >&2
							fails=$((fails + 1)) ;;
					esac
				done
				# THE OTHER HALF, and the one a reader of /etc/hosts alone would
				# miss: nss reaches `files` only when resolved is UNAVAIL (this
				# image's order is
				# `hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns`),
				# so on a HEALTHY VM the component that has to honour the pin is
				# systemd-resolved, which does so by reading /etc/hosts itself
				# (ReadEtcHosts, default yes). Turning that off would undo the pin
				# while leaving /etc/hosts looking correct. systemd's
				# parse_boolean() also takes `n` and `f`, so the spellings are
				# matched, not just the words. NOT covered: a drop-in under
				# resolved.conf.d/, which this image does not use.
				rconf=${gceToplevel}/etc/systemd/resolved.conf
				if grep -qiE '^[[:space:]]*ReadEtcHosts[[:space:]]*=[[:space:]]*(n|no|f|false|off|0)[[:space:]]*$' "$rconf"; then
					echo "FAIL: resolved is configured with ReadEtcHosts off; the /etc/hosts metadata pin would be bypassed on every healthy boot, since nss consults 'files' only when resolved is unavailable" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			gce-image-nix-conf = pkgs.runCommand "gce-image-nix-conf" { } ''
				fails=0
				conf=${gceToplevel}/etc/nix/nix.conf
				if grep -Eq '^require-sigs[[:space:]]*=[[:space:]]*false' "$conf"; then
					echo "FAIL: require-sigs is disabled in the image's nix.conf" >&2
					fails=$((fails + 1))
				fi
				subs=$(grep -E '^substituters[[:space:]]*=' "$conf" | cut -d= -f2- || true)
				for s in $subs; do
					case "$s" in
						https://cache.nixos.org|https://cache.nixos.org/|https://cache.numtide.com|https://cache.numtide.com/) ;;
						*) echo "FAIL: unexpected substituter '$s' in the image's nix.conf" >&2; fails=$((fails + 1)) ;;
					esac
				done
				# A trusted-substituters entry lets an unprivileged caller opt into a
				# cache the operator never vetted.
				extra=$(grep -E '^trusted-substituters[[:space:]]*=' "$conf" | cut -d= -f2- || true)
				if [ -n "$(echo "$extra" | tr -d '[:space:]')" ]; then
					echo "FAIL: trusted-substituters is non-empty: $extra" >&2
					fails=$((fails + 1))
				fi
				for key in 'cache.nixos.org-1:' 'niks3.numtide.com-1:'; do
					if ! grep -E '^trusted-public-keys[[:space:]]*=' "$conf" | grep -qF "$key"; then
						echo "FAIL: no trusted-public-key for $key; its substituter would fail closed or be unsigned" >&2
						fails=$((fails + 1))
					fi
				done
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The control CA is a BAKE-TIME input with no usable default, and the
			# runbook has to have a supported way to supply it. Without one an
			# operator builds `.#gce-image` literally, publishes an image whose
			# sshd trusts no CA, and every certificate cogworxd mints is refused
			# -- every instance wedges in Booting with a build-time warning as the
			# only diagnostic. The existing sshd check cannot see this: it greps
			# for `TrustedUserCAKeys`, which is set unconditionally regardless of
			# whether the file it points at has any content.
			gce-image-control-ca = pkgs.runCommand "gce-image-control-ca" {
				bakedCA = gceBakedCAText;
				defaultCA = gceDefaultCAText;
				bakedExtraCA = gceBakedExtraCAText;
			} ''
				fails=0
				# The DEFAULT config is fail-closed, deliberately: an empty file
				# admits nothing. This is asserted so that "the bake step is
				# optional" can never become true by accident.
				if [ -n "$(printf '%s' "$defaultCA" | tr -d '[:space:]')" ]; then
					echo "FAIL: the default gce host bakes a control CA; the fail-closed default is the only thing making the bake step mandatory" >&2
					fails=$((fails + 1))
				fi
				# The documented seam actually reaches sshd's TrustedUserCAKeys.
				case "$bakedCA" in
					*"${gceBakeCAKey}"*) ;;
					*) echo "FAIL: lib.mkGceHost's controlCAPublicKey override does not reach /etc/ssh/cogworx-control-ca.pub; the runbook's bake step would silently produce a CA-less image" >&2
						fails=$((fails + 1)) ;;
				esac
				# AND THE MERGE-ABLE SEAM, which exists because the alternative
				# regressed once: TrustedUserCAKeys is forced, so a composed
				# profile's own definition there loses with no error and no log
				# line. extraTrustedUserCAKeys is where such a CA is meant to land,
				# and it is only useful if BOTH keys survive into the one file sshd
				# reads -- the control CA it must never lose, plus the contributed
				# one, on separate lines (`sshkey_in_file` reads line by line).
				case "$bakedExtraCA" in
					*"${gceBakeCAKey}"*) ;;
					*) echo "FAIL: extraTrustedUserCAKeys displaced the baked control CA; the control channel would trust the wrong CA and every certificate cogworxd mints would be refused" >&2
						fails=$((fails + 1)) ;;
				esac
				case "$bakedExtraCA" in
					*"${gceBakeExtraCAKey}"*) ;;
					*) echo "FAIL: cogworx.gce.extraTrustedUserCAKeys does not reach /etc/ssh/cogworx-control-ca.pub; a composed profile's user CA has nowhere to land and would be dropped silently by the mkForce on TrustedUserCAKeys" >&2
						fails=$((fails + 1)) ;;
				esac
				if [ "$(printf '%s' "$bakedExtraCA" | grep -c .)" != 2 ]; then
					echo "FAIL: the baked CA file holds $(printf '%s' "$bakedExtraCA" | grep -c .) key lines, expected 2 (control CA + one contributed); a joined or blank-padded file is not what sshd parses" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The control account's local PAM rule must precede any remote
			# directory-backed account module added through extraModules.
			#
			# THE ORDER IS NOT ASSERTED HERE, on purpose. It is derived in the
			# module from the minimum order of every other account rule, and the
			# comparison lives in that module's `assertions` -- which is where it
			# has to be, because the config that ships is an operator bake with a
			# profile composed in and a flake check can only ever see the default
			# host. An assertion travels into that build; this derivation cannot.
			# What is left here is everything the assertion does NOT cover: the
			# rendered SHAPE of the rule, which no option comparison can see.
			gce-image-control-pam = pkgs.runCommand "gce-image-control-pam" {
				pamSshd = gcePamSshd;
			} ''
				fails=0
				printf '%s' "$pamSshd" > pam.sshd
				acct=$(grep '^account ' pam.sshd || true)
				first=$(printf '%s\n' "$acct" | head -n1)
				# FIRST, or it is not an exemption: a `default=bad`/`die` module
				# above it decides the phase before it is reached.
				case "$first" in
					*'pam_succeed_if.so quiet user = ${gceCfg.cogworx.gce.controlUser}'*) ;;
					*) echo "FAIL: the first sshd account rule is not the control user's local short-circuit, it is: $first" >&2
						echo "      a directory-backed account module above it refuses the control certificate whenever its daemon is down" >&2
						fails=$((fails + 1)) ;;
				esac
				# `sufficient` is what ENDS the phase. `optional`/`required` here
				# would let the stack carry on into the directory module and lose.
				case "$first" in
					'account sufficient '*) ;;
					*) echo "FAIL: the control user's account rule is not 'sufficient', so the account phase does not end at it: $first" >&2
						fails=$((fails + 1)) ;;
				esac
				# Matching on the PAM user NAME, not on uid: a uid comparison makes
				# pam_succeed_if resolve the account through NSS, which is the same
				# directory this rule exists to stay independent of.
				case "$first" in
					*' uid '*) echo "FAIL: the control user's account rule matches on uid, which sends pam_succeed_if through an NSS lookup -- the exemption must not depend on the directory it exempts" >&2
						fails=$((fails + 1)) ;;
				esac
				# And pam_unix must still stand behind it, so a NON-control user is
				# decided by a real module rather than by an empty stack.
				if ! printf '%s\n' "$acct" | grep -q '^account required .*pam_unix.so'; then
					echo "FAIL: the sshd account stack has no 'required pam_unix' behind the exemption" >&2
					fails=$((fails + 1))
				fi
				# The ACCOUNT stack is the only one this rule may appear in. A copy
				# that also landed in auth or session would be a second, unreviewed
				# exemption on a phase whose semantics are not the one reasoned
				# about here -- and it is the kind of thing a "make it symmetric"
				# edit adds. The order relationship is asserted in the module (see
				# above); this is the shape half.
				if [ "$(grep -c 'pam_succeed_if.so quiet user = ${gceCfg.cogworx.gce.controlUser}' pam.sshd)" != 1 ]; then
					echo "FAIL: the control user's pam_succeed_if rule appears $(grep -c 'pam_succeed_if.so quiet user = ${gceCfg.cogworx.gce.controlUser}' pam.sshd) times in the sshd PAM stack, expected exactly 1 (account only)" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The wrapper's --set / --set-default split, exercised rather than
			# grepped. gce-image-unit-ordering above only proves the three NAMES
			# appear in the wrapper, and that is exactly the check that passed while
			# the entire control-verb surface would fail because NixOS sets
			# `security.pam.services.sshd.startSession = true` whenever sshd uses PAM,
			# so pam_systemd exports XDG_RUNTIME_DIR=/run/user/0 into every
			# `ssh <vm> cogbox <verb>` BEFORE the wrapper runs, and --set-default
			# cannot override an already-set variable. cogbox then looked for
			# /run/user/0/cogbox-<name>/pid while the supervisor's runtime lives under
			# /run/cogbox, so `cogbox status` answered 3 (stopped) on a HEALTHY
			# sandbox and Terminal, Console, the liveness probe and every
			# rule/secret/plugin mutation went down behind it.
			#
			# So this runs the REAL wrapper with the PAM value already in the
			# environment, against a stub standing in for the cogbox binary, and pins
			# BOTH directions: XDG_RUNTIME_DIR must be forced, and the other two must
			# stay overridable (they are not set by anything in an ssh session, and a
			# break-glass operator pointing cogbox at another state tree is the reason
			# they are defaults). Flipping either is a decision, not a reflex -- if you
			# mean it, update the per-variable reasoning in gce/cogbox-host.nix too.
			gce-cogbox-wrapper-env = pkgs.runCommand "gce-cogbox-wrapper-env" {
				nativeBuildInputs = with pkgs; [ bash coreutils gnused gnugrep ];
			} ''
				fails=0
				sed 's|^exec .*|exec ${gceWrapperEnvStub} "$@"|' \
					${gceCogboxWrapper}/bin/cogbox > wrapper
				chmod +x wrapper
				if ! grep -q '${gceWrapperEnvStub}' wrapper; then
					echo "FAIL: could not retarget the wrapper's exec line at the stub; this check is vacuous" >&2
					exit 1
				fi
				val() { grep "^$1=" | cut -d= -f2-; }

				# 1. The PAM value must lose.
				got=$(XDG_RUNTIME_DIR=/run/user/0 ./wrapper | val XDG_RUNTIME_DIR)
				if [ "$got" != /run/cogbox ]; then
					echo "FAIL: the wrapper did not force XDG_RUNTIME_DIR: with pam_systemd's /run/user/0 already set, cogbox saw '$got'" >&2
					echo "      every control verb would address /run/user/0/cogbox-<name> while the supervisor runs under /run/cogbox" >&2
					fails=$((fails + 1))
				fi

				# 2. With nothing set, all three still carry the baked paths -- the
				#    original reason the wrapper exists (a bare `ssh host cmd` sources
				#    no profile, and cogbox with no config/data path exits 66).
				baked=$(env -u XDG_CONFIG_HOME -u COGBOX_DATA -u XDG_RUNTIME_DIR ./wrapper)
				for pair in \
					'XDG_CONFIG_HOME=${gceCfg.cogworx.gce.stateDir}/config' \
					'COGBOX_DATA=${gceCfg.cogworx.gce.stateDir}/data/cogbox' \
					'XDG_RUNTIME_DIR=/run/cogbox'; do
					if ! printf '%s\n' "$baked" | grep -qxF "$pair"; then
						echo "FAIL: an empty environment did not yield $pair; got: $(printf '%s' "$baked" | tr '\n' ' ')" >&2
						fails=$((fails + 1))
					fi
				done

				# 3. The two that PAM does not own stay overridable.
				got=$(XDG_CONFIG_HOME=/var/empty/alt-config ./wrapper | val XDG_CONFIG_HOME)
				if [ "$got" != /var/empty/alt-config ]; then
					echo "FAIL: XDG_CONFIG_HOME is now forced ('$got'); nothing in an ssh session sets it, and forcing it removes the break-glass override" >&2
					fails=$((fails + 1))
				fi
				got=$(COGBOX_DATA=/var/empty/alt-data ./wrapper | val COGBOX_DATA)
				if [ "$got" != /var/empty/alt-data ]; then
					echo "FAIL: COGBOX_DATA is now forced ('$got'); the name is cogbox-private, so no PAM module or unit can be setting it" >&2
					fails=$((fails + 1))
				fi

				# 4. The forced value must be the SAME runtime dir the supervisor uses.
				#    Neither side can detect a mismatch alone.
				rt=$(env -u XDG_RUNTIME_DIR ./wrapper | val XDG_RUNTIME_DIR)
				if ! grep -qF "XDG_RUNTIME_DIR=$rt" ${gceUnits}/cogworx-supervisor.service; then
					echo "FAIL: the wrapper forces XDG_RUNTIME_DIR=$rt but the supervisor unit does not use it; the control channel and the supervisor would address different sandboxes" >&2
					fails=$((fails + 1))
				fi

				# 5. A control-channel exec must learn the proxy uid split, and learn
				#    the SAME one the supervisor exports. This image runs the L7 proxy
				#    on its own uid, so the inject render has to grant that identity
				#    read on the cred files it names (rules/credgrant.zig) -- and binds
				#    arrive on THIS path (`cogbox secret add -n` + `secret reload`),
				#    which carries no unit Environment=. Unset here means the boot
				#    render grants and every later bind does not: a Claude connect on a
				#    running sandbox stays dead until a restart. A DIFFERENT value here
				#    means the two renders grant to two different groups, which is the
				#    same failure with an extra step.
				runas=$(env -u COGBOX_PROXY_RUNAS ./wrapper | val COGBOX_PROXY_RUNAS)
				if [ "$runas" = "<unset>" ] || [ -z "$runas" ]; then
					echo "FAIL: the wrapper exports no COGBOX_PROXY_RUNAS, so a control-channel bind cannot grant the dropped L7 proxy read access to the credential it just bound" >&2
					fails=$((fails + 1))
				elif ! grep -qF "COGBOX_PROXY_RUNAS=$runas" ${gceUnits}/cogworx-supervisor.service; then
					echo "FAIL: the wrapper exports COGBOX_PROXY_RUNAS=$runas but the supervisor unit exports something else; the boot render and the bind render would grant to different groups" >&2
					fails=$((fails + 1))
				fi

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The supervisor's orderings and refusals, none of which are visible in
			# the unit file. See tests/test_supervise.sh for what each case guards.
			gce-supervise-tests = pkgs.runCommand "gce-supervise-tests" {
				nativeBuildInputs = with pkgs; [ bash coreutils gawk gnugrep ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_supervise.sh} ${./gce/supervise.sh}
				touch $out
			'';

			# The floor's RENDERED ruleset, its probe POLARITIES, and its live
			# PACKET behaviour. None of the three is visible in the unit file, and
			# none is something a grep over a printf format string can really
			# prove, so this runs the real install leg against a file:// metadata
			# tree and asserts on the nft file it writes, runs the real verify leg
			# on a machine with no floor loaded at all, and finally loads the
			# rendered ruleset into a throwaway user+network namespace and probes
			# it with a REAL LISTENER bound on an exempt port. The cases cover a
			# rule-2 deny with no skuid match, an exception probe that needs a
			# listener before the supervisor starts passt, narrowing to named
			# uids, and a deny that eats a real listener's SYN-ACK.
			# util-linux/nftables/iproute2
			# are for that last section, which SKIPS where the kernel cannot host
			# it. See tests/test_floor.sh.
			# systemd is here for the same reason the verifier reaches for it:
			# section 5's rule-3 cases need a REAL listener on loopback, and
			# systemd-socket-activate is already in this image's closure, so
			# testing the floor adds no network utility to it.
			gce-floor-tests = pkgs.runCommand "gce-floor-tests" {
				nativeBuildInputs = with pkgs; [ bash coreutils gnugrep util-linux nftables iproute2 systemd ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_floor.sh} ${gceFloorInstall} ${gceFloorVerify}
				touch $out
			'';
		});

		nixosConfigurations = lib.listToAttrs (map (system: {
			name = configName system;
			value = mkMicrovm system "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules system {};
			};
		}) supportedSystems)
		# The CONTAINER config exposed as a buildable nixosConfiguration so the
		# per-instance FULL toplevel builds via `--override-input userExtensions`
		# (prebuildToplevelLocal / agentInit's realise target). SAME args as the
		# let-bound containerSystem the agent-image bakes, so the base (no-plugin)
		# toplevel here is the SAME derivation agentInit falls back to. This MUST be
		# a separate attr from the VM `cogbox-<arch>`: `system.build.toplevel` is
		# target-DEPENDENT -- the VM config's toplevel is a QEMU-guest system that
		# cannot boot as an unprivileged container (unlike the target-independent brain).
		// lib.listToAttrs (map (system: {
			name = "${configName system}-container";
			value = mkContainer system "cogbox" {
				extraModules = cogboxModules system { target = "container"; };
			};
		}) supportedSystems) // {
			# The GCE backend HOST system (see mkGceHost). x86_64 only: GCE
			# nested virtualization is offered on Intel machine series only
			# so there is no aarch64/riscv64 twin to generate.
			# `packages.gce-image` builds this config's googleComputeImage; the
			# gce-image-* checks assert its closure, userland and unit graph
			# without needing the image itself.
			cogbox-x86_64-gce = mkGceHost "x86_64-linux" { };

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
			# Same idea for Phase Q (`cogbox plugin`): the generated
			# composition flake wraps the plugin modules and the (no-op
			# scaffold) user module in an `imports` list. That nesting
			# changes module flattening order, which changes
			# environment.systemPackages ORDER, which changes the
			# system-path drv -- so the flat test-hello fixture above does
			# NOT cache-hit for the plugin path. Pre-build the runner with
			# the exact same nested shape the composition produces: two
			# plugins from one flake (default = hello, extra = etc marker)
			# plus the scaffold's no-op module, in add order, user last.
			cogbox-x86_64-test-plugin = mkMicrovm "x86_64-linux" "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules "x86_64-linux" {
					userExt = {
						imports = [
							({ pkgs, ... }: {
								environment.systemPackages = [ pkgs.hello ];
								system.extraDependencies = [ pkgs.hello ];
							})
							({ ... }: {
								environment.etc."cogbox-test-extra".text = "extra\n";
							})
							({ pkgs, lib, ... }: { })
						];
					};
				};
			};
			# Fixture: a populated cogbox.* config, for the brain-materialization
			# VM test (Phase brain) and local brain builds.
			cogbox-x86_64-brain-fixture = mkMicrovm "x86_64-linux" "cogbox" {
				vcpu = 4;
				mem = 4096;
				extraModules = cogboxModules "x86_64-linux" {
					userExt = { pkgs, lib, ... }: {
						cogbox = {
							contents = ./tests/fixtures/brain-plugin/contents;
							mcp.demo-mcp = { command = "demo-mcp-server"; args = [ "--stdio" ]; env = { DEMO_MODE = "ro"; }; };
							env = { DEMO_URL = "http://demo.example.com"; };
							# Plugin tools -> cogbox-brain's $out/bin (prepended to the
							# container PATH). hello is the smallest real package; the brain
							# build below asserts $out/bin/hello resolves.
							packages = [ pkgs.hello ];
							settings.claude-code = { model = "claude-opus-4-8"; };
							settings.opencode = { model = "anthropic/claude-opus-4-8"; };
							hooks.SessionStart = "true";
						};
					};
				};
			};
			# CONTAINER analogue of the brain fixture above. The brain output is
			# target-INDEPENDENT (identical runCommandLocal drv in both configs),
			# but the container brain-materialize oneshot rebuilds it by evaluating
			# THIS `-container` config -- so the container-brain-command check builds
			# it here to exercise exactly the guest-half delivery path (commands /
			# packages) when the boot rebuild evaluates the container config.
			cogbox-x86_64-brain-fixture-container = mkContainer "x86_64-linux" "cogbox" {
				extraModules = cogboxModules "x86_64-linux" {
					target = "container";
					userExt = { pkgs, lib, ... }: {
						cogbox = {
							contents = ./tests/fixtures/brain-plugin/contents;
							mcp.demo-mcp = { command = "demo-mcp-server"; args = [ "--stdio" ]; env = { DEMO_MODE = "ro"; }; };
							env = { DEMO_URL = "http://demo.example.com"; };
							packages = [ pkgs.hello ];
							settings.claude-code = { model = "claude-opus-4-8"; };
							settings.opencode = { model = "anthropic/claude-opus-4-8"; };
							hooks.SessionStart = "true";
						};
					};
				};
			};
		};
	};
}
