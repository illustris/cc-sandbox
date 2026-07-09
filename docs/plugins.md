# Plugins

Plugins package the [per-instance extension pattern](extensions.md) into something installable: a git repo (or any flake source) that carries a NixOS module **and** the agent-facing kit it contributes (skills, agents, commands, rules), plus the host-side firewall/credential policy it needs. `cogbox plugin add` is the CLI workflow for what previously required hand-editing the instance flake and hand-merging rules.

```sh
cogbox plugin add github:myorg/myplugin?dir=flake            # install into the default instance
cogbox plugin add 'github:org/observability#loki' -n work    # one module of a multi-plugin flake
cogbox plugin resolve github:org/observability#loki          # preview (JSON) -- installs nothing
cogbox plugin update                                          # re-resolve and re-pin everything
cogbox plugin del myplugin                                    # remove module + its firewall rules
```

## The contract

A plugin is a flake that exposes two outputs:

- **`nixosModules.<attr>`** — a standard, reusable NixOS module. It carries ordinary guest config (packages, services, mounts) **and** the plugin's agent-facing contributions under the `cogbox.*` option tree the base declares (see [The kit](#the-kit-cogbox)). Selected by the URL fragment (`URL#attr`); a bare URL means the `default` module. `pkgs` resolves to cogbox's nixpkgs (same caveat as the [extension scaffold](extensions.md#which-nixpkgs-pkgs-is)).
- **`cogboxPlugins.<attr>`** — a thin registration: `{ module = self.nixosModules.<attr>; networkRules; l7Rules; inject; }`. This is the host-side, **hot-reloadable** network/auth policy, read at `cogbox plugin add` with a cheap isolated `nix eval` (no cogbox-system context, IFD-blocked) and merged into `config.json` — applied to the running firewall/proxy **without a rebuild**.

`cogbox plugin add URL` installs `cogboxPlugins.default`; `add URL#loki` installs `cogboxPlugins.loki` (and imports its `.module`). `module` is optional — a **pure-policy** plugin (only firewall/inject, no guest content) omits it and cogbox treats it as the empty module.

### The organizing principle — hot-reload decides where a thing lives

- **Host-side, hot-reloadable policy** (`networkRules`/`l7Rules`/`inject`) lives in the `cogboxPlugins.<attr>` flake output. It is read at `add` by a cheap `nix eval`, stored in `config.json`, and applied to the running firewall/proxy **without a rebuild**. It is never rendered inside the guest.
- **Build-time guest content** (the kit, and any packages/services) lives in the **NixOS module** as `cogbox.*`. A change there already requires a rebuild/restart, so it belongs in the build, where it is evaluated with cogbox's `pkgs` and folded into the guest by the base. Ship a plugin's CLI tools via **`cogbox.packages`** (not raw `environment.systemPackages`) so they land on PATH on *both* the VM and the container backends — see [The kit](#the-kit-cogbox).

A complete mid-complexity plugin:

```nix
{
  description = "cogbox druid-es: Druid performance-analysis agent over an Elasticsearch cluster";

  outputs = { self }: {

    # Everything built into the guest -- the kit AND ordinary NixOS config.
    nixosModules.default = { pkgs, ... }: {
      cogbox = {
        contents = ./contents;                  # scan contents/{skills,agents,commands,rules}
        env.ES_URL = "http://es-1.example.internal:9200";
        settings.claude-code.model = "claude-opus-4-8";
        packages = [ /* es-*, druid-* helper bins */ ];   # tools on the sandbox PATH (both backends)
      };
    };

    # Thin registration: which module is the plugin, plus host-side policy.
    cogboxPlugins.default = {
      module  = self.nixosModules.default;
      l7Rules = [ { allow = "es-1.example.internal"; terminate = true; comment = "ES data node 1"; } ];
      inject  = [ { host = "es-1.example.internal"; style = "basic"; secret = "es-creds"; port = 9200; } ];
    };
  };
}
```

The directory **is** the manifest:

```
data-druid-es/
├── flake.nix
├── bin/                       es-cat, es-search, druid-metric, ...
└── contents/
    ├── skills/{overview,es-query,druid-metrics}/SKILL.md
    ├── agents/druid-investigator.md      # standard agent file (name/description/model frontmatter + body)
    ├── commands/druid-rca.md
    └── rules/read-only.md                # optional; empty `paths` frontmatter => always-on
```

`FLAKE_URL` can be anything nix accepts: `github:owner/repo`, `git+https://...`, `path:/abs/dir`, with `?dir=` for flakes in a subdirectory. The `#attr` fragment is restricted to `[a-zA-Z0-9_-]`. Plugin names follow the instance-name grammar; `user` is reserved.

## The kit: `cogbox.*`

The base declares one option tree; each plugin module fills in its slice, and the module system merges across all imported plugins:

| Option | Type | Meaning |
|---|---|---|
| `cogbox.contents` | path \| list of paths | Convention root(s) scanned (`readDir`, pure eval) for `skills/`, `agents/`, `commands/`, `rules/`. Roots concatenate across plugins. |
| `cogbox.skills` / `.agents` / `.commands` / `.rules` | attrset name→path | Explicit units that compose on top of (and override) discovery — e.g. a *generated* skill dir. |
| `cogbox.mcp` | attrset name→`{command/args/env}` \| `{url/headers}` | Neutral MCP servers, materialized per harness. |
| `cogbox.hooks` | attrset event→command | Lifecycle hooks. |
| `cogbox.env` | attrset string→string | Plugin endpoints, merged into the harness launcher env (never a hard global `environment.variables`). |
| `cogbox.packages` | list of packages | Tools placed on the sandbox PATH. **Use this, not `environment.systemPackages`, for a plugin's CLIs.** The base folds them into `environment.systemPackages` on the VM (baked into the runner) **and** into the brain's `$out/bin` prepended to PATH on the container — so tools reach *both* backends. `environment.systemPackages` alone reaches only the VM (the container image is built plugin-less), so a plugin that ships tools that way has them silently missing on the container even though its skills materialize. |
| `cogbox.settings.<harness>` | `{ model; reasoningEffort }` | Per-harness settings. **Allowlist: `model`, `reasoningEffort` only** (enforced by the option type) — never permissions/auth/providers. Keyed `claude-code` / `opencode` / `codex`. |

**Discovery.** A skill is a directory containing `SKILL.md`; an agent/command/rule is a `<name>.md` file. The skill's `name:` frontmatter must equal its directory name (opencode requirement). Non-conforming entries (`README.md`, a dir without `SKILL.md`) are skipped.

**Names are natural — no namespacing.** A skill is `/druid-rca`, not `/druid-es-druid-rca`. Uniqueness, not prefixing, is the invariant: a discovered-name collision across `contents` roots, or two plugins defining the same explicit name, **fails the build** with a plugin-attributed message. Name generically-named units distinctly.

**Two deliberate non-features**, enforced by the contract shape:

- **Plugins set no cwd and no `loginShellInit`.** The workdir (`~/work`) and cwd are 100% base-owned, so the cwd fight between plugins is structurally impossible.
- **Plugins ship no always-on `CLAUDE.md`/`AGENTS.md`.** Orientation is relevance-loaded skills (listed in the cogbox-authored index) plus an optional path-scoped `rules/` channel (a rule with empty `paths` ⇒ always-on). There is no channel for a third party to inject always-on, user-outranking prose.

## The workdir: `~/work`

`~/work` is a base-created symlink into the persisted 9p share (`/var/lib/cogbox/work`); HOME stays `/root`. It is the standardized project dir: agents and users land there (`loginShellInit` and the `c`/`oc`/`cx` launchers `cd ~/work`), it survives restarts, and it is host-visible under `~/.local/share/cogbox/instances/<name>/data/work/`.

At build, the base folds every plugin's merged `config.cogbox` into **one derivation** (`cogbox-brain`) laying out each enabled harness's native tree + merged config + a cogbox-authored capability **index** skill. At boot, one base-owned oneshot (modeled on `load-ssh-keys`) materializes it:

```
~/work/.cogbox/brain      -> the cogbox-brain store derivation (RO leaves)
~/work/.claude/skills/<s>  -> child symlinks into the RO leaves (parents stay real writable dirs)
~/work/.claude/agents/<a>.md, .claude/commands/<c>.md, .claude/rules/<r>.md
~/work/.opencode/{skills,agents,commands}/...   (opencode.json read via OPENCODE_CONFIG)
~/work/.agents/skills/...                        (codex skills)
```

The base drops only **child** symlinks into real writable dirs (never a whole-dir or whole-file link), so the harness can scaffold session state alongside and peers coexist. A single base oneshot pre-accepts Claude Code workspace trust for `~/work`.

## Harness-agnostic → native mapping

One neutral unit → each enabled harness's native layout (gated on which harnesses the instance uses):

| Neutral | claude-code | opencode | codex | pi | hermes-agent |
|---|---|---|---|---|---|
| **skill** `<s>` | `.claude/skills/<s>/SKILL.md` | `.opencode/skills/<s>/SKILL.md` | `.agents/skills/<s>/SKILL.md` | `.agents/skills/<s>/SKILL.md` (native project discovery) | `~/.hermes/skills/<s>/SKILL.md` (overlay upper; no project discovery) |
| **rule** `<r>` | `.claude/rules/<r>.md` (`paths:`; empty ⇒ always-on) | `instructions` glob in `opencode.json` | `AGENTS.md` digest (always-on) | `AGENTS.md` digest (always-on) | `AGENTS.md` digest (always-on) |
| **agent** `<a>` | `.claude/agents/<a>.md` | `.opencode/agents/<a>.md` | (best-effort) | -- | -- |
| **command** `<c>` | `.claude/commands/<c>.md` | `.opencode/commands/<c>.md` | skill `.agents/skills/<c>` | -- | -- |
| **mcp** `<srv>` | `.mcp.json` `mcpServers` | `opencode.json` `mcp` | `config.toml` `[mcp_servers]` | -- | -- |
| **settings** | `.claude/settings.json` | `opencode.json` | `config.toml` | -- | -- |
| **env** | launcher env | launcher env | launcher env | launcher env | launcher env |
| **index** | `.claude/skills/cogbox-plugins/` | `.opencode/skills/cogbox-plugins/` | `.agents/skills/cogbox-plugins/` | `.agents/skills/cogbox-plugins/` | `~/.hermes/skills/cogbox-plugins/` |

The same store copy is symlinked into each layout (no duplication). codex agent/command fidelity is best-effort (claude-only frontmatter is dropped; read-only relies on prompt + egress lockdown). codex, pi, and hermes have no native per-file rules dir, so the merged rules are concatenated into one `AGENTS.md` digest linked at `~/work/AGENTS.md` (only-if-absent, never clobbering a user file); `paths:`-scoped rules become always-on there. pi and codex share the same `.agents/skills/` tree (agentskills.io layout); hermes only loads `$HERMES_HOME/skills`, so its links go into the per-instance overlay upper of `~/.hermes` (the host dir is untouched). pi/hermes have no plugin MCP, settings, agent, or command mapping yet.

## Network rules and credential injection

`cogboxPlugins.<attr>.networkRules` (L4 CIDR), `.l7Rules` ([L7 vhost rules](network-filtering.md#l7-host-filtering)), and `.inject` ([credential injection](network-filtering.md#host-side-credential-injection)) are the host-side, hot-reloadable policy. If the plugin declares any and the instance is in `rules` mode, `add` shows them all and asks once before merging (auto-confirmed with `-y` or when stdin is not a tty). Injection gets its own louder confirmation section (granting a host-side credential is a different trust than a firewall rule) and prints a `cogbox secret add` bind checklist — the secret is named symbolically and **never** enters the guest.

Each merged rule/spec carries a `"plugin": "<name>"` field, so `del`/`update` remove or replace exactly what that plugin brought in. **Rule/inject changes hot-reload** into a running instance; **kit/module changes need a `cogbox restart`** — that asymmetry is the §"organizing principle" above. An `mcp` server may name only `command`/`args`/`env`/`url`/`headers` — a token/cred_file/secret path is rejected (MCP auth goes through host-side inject, never inline).

See [Credential injection](network-filtering.md#host-side-credential-injection) for the full security model and the [`cogbox secret`](network-filtering.md#the-secret-store) reference.

## Pinning and updates

Versioning is per flake, not per plugin. `add` resolves the URL with `nix flake metadata`, records the locked URL, rev, and narHash in `config.json` (`.plugins`), and runs `nix flake archive` so the plugin and its transitive inputs land in the local store — subsequent starts resolve the pins offline.

Enabling another module of an already-installed flake **reuses the existing pin**, so all plugins from one flake stay at one rev; `update` resolves each distinct URL once (with `nix flake metadata --refresh`, bypassing nix's eval cache so a mutable ref like `github:owner/repo` actually re-resolves to the current tip) and moves all of its plugins together. To hold a flake at a specific rev, pin it in the URL (`...?rev=<sha>` or `github:owner/repo/<sha>`). A **dirty git worktree** is the worst-pinned shape (no rev, no narHash in the URL); `add` warns — commit, then `cogbox plugin update` to pin properly.

A `.plugins` entry:

```json
{
    "name": "loki",
    "url": "github:org/observability",
    "attr": "loki",
    "lockedUrl": "github:org/observability/<rev>?narHash=sha256-...",
    "rev": "<rev>",
    "narHash": "sha256-..."
}
```

`url` is what you typed (minus the fragment) and is what `update` re-resolves; `lockedUrl` is what the composition flake's inputs consume. `attr` is omitted for the default module.

## The composition flake

Plugin state is materialized as a generated flake at `~/.config/cogbox/instances/<name>/plugins-flake/flake.nix` (marked DO NOT EDIT; regenerated from `config.json` by every `plugin` command). It declares one pinned input per plugin plus the instance's own `flake/` as input `user`, and exposes a single `nixosModules.default` importing each plugin's module via its registration, user module last:

```nix
# GENERATED by 'cogbox plugin' -- DO NOT EDIT.
{
    inputs = {
        user.url = "path:/home/me/.config/cogbox/instances/default/flake";
        "p-mimir".url = "github:org/observability/<rev>?narHash=sha256-...";
        "p-loki".url  = "github:org/observability/<rev>?narHash=sha256-...";
    };
    outputs = { self, user, ... }@inputs: {
        nixosModules.default = {
            imports = [
                (inputs."p-mimir".cogboxPlugins."default".module or {})
                (inputs."p-loki".cogboxPlugins."loki".module or {})
                user.nixosModules.default
            ];
        };
    };
}
```

`(... .module or {})` makes the module optional (a pure-policy plugin omits it). At launch, when `.plugins` is non-empty, the wrapper points `--override-input userExtensions` at this flake, so plugins and manual flake.nix edits compose. Because the inputs are pinned and pre-fetched by `nix flake archive`, restarts of a plugin-bearing instance work offline once the runner is built.

## Preview before install: `cogbox plugin resolve`

`cogbox plugin resolve URL[#attr] [--git-credential-stdin]` is a read-only preview: it runs flake metadata + the `cogboxPlugins.<attr>` contract check + the host-side `networkRules`/`l7Rules`/`inject` readout and prints **one JSON line** on stdout (`{name, attr, url, lockedUrl, rev, narHash, dirty, present, networkRules, l7Rules, inject}`). It mutates nothing — no config, no source materialization, no composition. It is the foundation for the cogworx plugin store's truthful pre-install posture preview.

## Trust

Adding a plugin evaluates third-party nix code at add time (pure eval, IFD disabled) and *builds* it into the guest at the next start. Treat `cogbox plugin add` like installing software: only add flakes you trust. The contract removes the always-on prompt-injection channel and the cwd fight by construction, sanitizes plugin-authored descriptions before they reach the cogbox-authored index, and surfaces the egress/credential ask for confirmation — but a skill body is still arbitrary plugin prose loaded on relevance. The boundary remains "only add plugins you trust."

## Plugin verb reference

| Form | Description |
|---|---|
| `cogbox plugin list [-n NAME]` | List installed plugins with their pinned revision and rule count |
| `cogbox plugin add FLAKE_URL[#ATTR] [--as PLUGIN] [-y] [-n NAME]` | Resolve, pin, and install. `#ATTR` selects `cogboxPlugins.<attr>` (default: `default`). `--as` overrides the derived name; `-y` skips the confirmation. |
| `cogbox plugin resolve FLAKE_URL[#ATTR] [--git-credential-stdin]` | Preview (JSON) the contract + host-side rules/inject without installing |
| `cogbox plugin del PLUGIN [-y] [-n NAME]` | Remove a plugin and exactly the network rules it brought in |
| `cogbox plugin update [PLUGIN] [-n NAME]` | Re-resolve the original URL(s), re-pin, and replace the plugins' tagged rules |
