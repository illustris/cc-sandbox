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
		nixfs = {
			url = "github:illustris/nixfs";
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
		mkHarnesses = system: pkgs: lib.filterAttrs (_: h: h.enable) {
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
					boot.kernelParams = [ "systemd.hostname=cogbox-@cogbox-instance@" ];
					users.users.root.password = "";
					services.getty.autologinUser = "root";
					# Land interactive login shells in the persisted data
					# dir so the autologin session starts where the user's
					# state lives, rather than in root's home.
					# Land interactive login shells in the standardized workdir
					# ~/work (= /root/work, a base-created symlink into the persisted
					# share). mkForce so no plugin can append a competing `cd` -- the
					# cogbox.* contract has no loginShellInit surface. Falls back to
					# the share root if the brain oneshot has not run yet.
					programs.bash.loginShellInit = lib.mkForce ''
						cd /root/work 2>/dev/null || cd /var/lib/${name}
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
						users.users.root.password = "";
						# Land login + non-login shells in ~/work, same as the VM
						# (mkForce: no plugin appends a competing cd). Falls back to
						# the mounted state root before the brain oneshot has run.
						programs.bash.loginShellInit = lib.mkForce ''
							cd /root/work 2>/dev/null || cd /var/lib/cogbox-state/data/cogbox
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

		# `userExt` defaults to the no-op userExtensions input but can be
		# overridden by tests to inject a known module in the same list
		# position the runtime override-input would, so the resulting
		# microvm runner has a deterministic .drvPath that matches what
		# `nix run --override-input userExtensions ...` produces.
		cogboxModules = system: { userExt ? inputs.userExtensions.nixosModules.default, target ? "vm" }: let
			hasNixMcp = builtins.hasAttr system (nix-mcp.packages or {});
		in [
			inputs.nixfs.nixosModules.nixfs
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
					in "#!${pkgs.runtimeShell}\n"
						+ "cd /root/work 2>/dev/null || true\n"
						+ ''exec env ${envStr} ${lib.getExe h.package} ${flagsStr} "$@"''
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
				'' + lib.optionalString (harnesses ? "codex") ''
					mkdir -p $out/agents/skills
					${linkInto "$out/agents/skills" "" skills}
					ln -s ${indexSkill} $out/agents/skills/cogbox-plugins
					${lib.optionalString (codexConfigAttrs != {}) "mkdir -p $out/codex && cp ${codexConfig} $out/codex/config.toml"}
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
						echo "cogbox-brain: rebuilding per-instance brain ($pcount plugin(s)) for instance '$inst'" >&2
						if out=$(${pkgs.nix}/bin/nix build --no-link --print-out-paths \
								--extra-experimental-features "nix-command flakes" \
								"''${subst[@]}" \
								--override-input userExtensions "path:$icd/plugins-flake" \
								--override-input userExtensions/user/nixpkgs "path:${nixpkgs}" \
								"path:${self}#nixosConfigurations.${configName system}.config.system.build.cogboxBrain"); then
							first=$(printf '%s\n' "$out" | grep -m1 '^/nix/store/' || true)
							if [ -n "$first" ] && [ -e "$first" ]; then
								brain="$first"
								echo "cogbox-brain: using per-instance brain $brain" >&2
							else
								echo "cogbox-brain: rebuild produced no out-path; using baked base brain" >&2
							fi
						else
							echo "cogbox-brain: rebuild failed; using baked base brain (see prior nix log)" >&2
						fi
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

					# codex: skills under ~/.agents/skills; global config.toml only if absent
					linkleaves "$brain/agents/skills" "$WORK/.agents/skills"
					if [ -e "$brain/codex/config.toml" ] && [ ! -e /root/.codex/config.toml ]; then
						mkdir -p /root/.codex
						install -m600 "$brain/codex/config.toml" /root/.codex/config.toml || true
					fi
				'';

				# Pre-accept Claude Code workspace trust for ~/work (both /root/work
				# and the /var/lib/cogbox/work it resolves to, since Node's cwd
				# resolves the symlink) and reconcile stale pre-migration project
				# keys. Replaces the per-plugin cogbox-claude-trust units.
				brainTrustScript = pkgs.writeShellScript "cogbox-brain-trust" ''
					set -eu
					f=/root/.claude.json
					[ -s "$f" ] || echo '{}' > "$f"
					${pkgs.jq}/bin/jq '
						.projects["/var/lib/cogbox/work"].hasTrustDialogAccepted = true
						| .projects["/root/work"].hasTrustDialogAccepted = true
						| del(.projects["/var/lib/cogbox"])
						| del(.projects["/var/lib/cogbox/home"])
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
					# A minimal, non-secret ~/.claude.json must exist for claude-code to
					# skip /login (the credential file alone is not enough). brain-trust
					# enriches it (workspace trust); seed an empty object if absent.
					[ -e "$cjson" ] || printf '{}\n' > "$cjson"
					chmod 600 "$cjson"
					ln -sfn "$cdir" /root/.claude
					ln -sfn "$cjson" /root/.claude.json

					# Stage (marker present) or remove (absent) the redacted stub. The
					# verb single-sources the stub sentinel from the secret module and
					# never writes a real token.
					${self.packages.${system}.cogbox-container}/bin/cogbox __claude-stub "$cdir" "$marker"
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

				services.openssh.enable = lib.mkIf isVm true;
				# `cogbox ssh` pins to a single key with IdentitiesOnly +
				# IdentityAgent=none (see zig/src/cli/verbs/ssh.zig), so its
				# default path makes exactly one auth attempt and can't exhaust
				# the limit. The generous cap is kept for the --no-auto-keys
				# opt-out path, where ssh falls back to the user's agent and
				# ~/.ssh keys and a busy agent could otherwise burn through the
				# default 6 attempts before a working key is reached. This guest
				# is a local, ephemeral, single-user sandbox (sshd bound to
				# 127.0.0.1), so a generous cap is safe.
				services.openssh.settings.MaxAuthTries = lib.mkIf isVm 50;

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
				++ lib.optional isContainer self.packages.${system}.cogbox-container;

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
							++ lib.optional (isVm && harnesses ? "codex") "${utils.escapeSystemdPath "/root/.codex"}.mount";
						requires = [ stateUnit ];
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
					# ~/work resolve like it does in the VM. The brain/trust oneshots
					# (reused verbatim) hardcode /var/lib/cogbox as the data dir, so
					# symlink it into the mounted state before they run.
					cogbox-container-state = lib.mkIf isContainer {
						description = "Prepare mounted state + ~/work resolution (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "cogbox-container-state" ''
								set -e
								mkdir -p ${cogboxData} ${stateRoot}/config /run/cogbox
								ln -sfn ${cogboxData} /var/lib/cogbox
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
					cogbox-claude-stub = lib.mkIf isContainer {
						description = "Stage/remove the redacted Claude stub credential (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" "cogbox-brain-materialize.service" "cogbox-brain-trust.service" ];
						after = [ "cogbox-container-state.service" ];
						requires = [ "cogbox-container-state.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# cogbox resolves XDG/HOME before any verb dispatch; mirror
							# cogbox-init so the boot run has them (the verb itself takes
							# explicit path args and holds no secret).
							Environment = [
								"HOME=/root"
								"XDG_CONFIG_HOME=${stateRoot}/config"
								"COGBOX_DATA=${cogboxData}"
							];
							ExecStart = claudeStubScript;
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
				exec ${containerToplevel}/init
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
				extraCommands = "mkdir -m 1777 -p tmp var/tmp && mkdir -m 0700 -p root && rm -f etc";
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
		});

		checks = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
		in {
			# Pure-helper parity + credential-injection unit tests for the
			# mitmproxy L7 addon. Fast (no VM); keeps the addon's host
			# pattern / path / cred-injection logic honest on every build.
			addon-tests = pkgs.runCommand "cogbox-addon-tests" {
				nativeBuildInputs = [ pkgs.python3 ];
			} ''
				cp ${./l7-mitm-addon.py} l7-mitm-addon.py
				mkdir tests
				cp ${./tests/test_l7_addon.py} tests/test_l7_addon.py
				python3 tests/test_l7_addon.py
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
