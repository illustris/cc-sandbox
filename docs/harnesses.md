# Harnesses

A *harness* is a coding-agent CLI that cogbox installs in the guest and mounts host state for. The currently-supported harnesses are `claude-code` (launcher: `c`), `opencode` (launcher: `oc`), `codex` (launcher: `cx`), `hermes-agent` (launcher: `h`), and `pi` (launcher: `p`). Codex is opt-in and disabled by default (its Rust build is slow) -- set `enableCodex = true` in `flake.nix` to build it in. When a harness is not built in, its launcher, mounts, and host-state seeding are all omitted (the launcher's `HARNESSES` list is generated from the same `mkHarnesses` set).

## The harness model

The model is symmetric and opt-in:

- **All harness binaries are always installed** in the guest (subject to per-architecture availability), so any active VM has every launcher on `$PATH`.
- **Host state is created only for harnesses you actually use.** On first init, the wrapper checks for any pre-existing harness config on the host and treats those harnesses as active. If none are found, it prompts you to choose. The active list is recorded at `<datadir>/.config/active-harnesses`.
- **A single overlay image** (`harness-overlay.img`) backs persistent state for all harnesses, with per-harness subdirectories inside (`/var/lib/harness-rw/<harness>/<pathkey>/{upper,work}` and `/var/lib/harness-rw/<harness>/{cache,state}` for ephemeral paths). Resizing `overlaySize` covers all harnesses at once.

Host state shared across all instances:

| Harness | Host config | Host auth/data |
|---|---|---|
| claude-code | `~/.claude/` | `~/.claude.json` |
| opencode | `~/.config/opencode/` | `~/.local/share/opencode/` (includes `auth.json`) |
| codex | `~/.codex/` | `~/.codex/` (includes `auth.json`) |
| hermes-agent | `~/.hermes/` | `~/.hermes/` (includes `.env` with provider API keys) |
| pi | `~/.pi/` | `~/.pi/` (includes `agent/auth.json`) |

Inside the guest, host config dirs are mounted read-only (9p) as overlay lowerdirs, with each instance's writes captured in its own overlay image -- so per-instance harness settings persist independently while authentication stays shared. Single-file auth tokens are injected at boot via `fw_cfg`.

> **Note on credentials in the sandbox.** Mounting the host's auth this way also exposes the harness's long-lived secrets (for the OAuth harnesses, the **refresh token** in `.credentials.json` / `auth.json`) to a potentially-compromised agent inside the VM. To keep those out of the sandbox, see [host-side credential injection](network-filtering.md#host-side-credential-injection): the terminate-tier proxy injects the real token host-side so the guest only carries a **redacted, still-logged-in placeholder** (present and scoped, not the real token). For claude-code you can also run `/login` **inside** the guest to use a different account -- that login persists in that instance only, and the guest stops inheriting the host token (clear it to resume inheritance). See [In-VM login](network-filtering.md#in-vm-login-per-instance-isolated).

To add a harness after init, either create its host config dir manually and re-launch, or set `COGBOX_<HARNESS>_<KEY>` to point at an existing dir (see [host-side path overrides](internals.md#host-side-path-overrides)).

A note about `node_modules/`: if a host harness config dir contains a `node_modules/` tree, it is exposed read-only into the VM via the 9p lowerdir share. To avoid streaming hundreds of megabytes through 9p on every boot, keep heavy package installs out of harness config dirs.

## Plugin kits per harness

Independently of the shared host config above, [plugins](plugins.md) contribute an agent-facing **kit** (skills/agents/commands/rules + merged MCP/settings) via the `cogbox.*` module options. The base materializes one neutral kit into each enabled harness's native layout under the project workdir `~/work` — `.claude/`, `.opencode/`, the `.agents/skills/` tree shared by codex and pi, hermes's `~/.hermes/skills/` (per-instance overlay upper), and a harness-neutral `AGENTS.md` rules digest (read by pi, hermes, and codex; linked only-if-absent) — so the same plugin serves every harness. pi/hermes gaps: no plugin MCP, settings, agent, or command mapping yet. Plugin *tools* reach every harness via the shared `PATH` prepend. This is project-scoped (per instance, in `~/work` — hermes's skill links land in the per-instance overlay upper of `~/.hermes`), not part of the shared host config. See [plugins.md](plugins.md#harness-agnostic--native-mapping) for the mapping table.

## How "full auto" is wired per harness

- `c` (claude-code) sets `IS_SANDBOX=1` and passes `--dangerously-skip-permissions`.
- `oc` (opencode) sets `OPENCODE_PERMISSION='{"edit":"allow","bash":"allow","webfetch":"allow","doom_loop":"allow","external_directory":"allow"}'`. Opencode `JSON.parse`s that env var and merges it into `config.permission`. As of opencode 1.16.2 the value must be the object form keyed by permission category (`edit`/`bash`/`webfetch`/`doom_loop`/`external_directory`, each `ask|allow|deny`; `bash` may also be a `{pattern: action}` map) -- the old bare-string shorthand `"allow"` is rejected with a fatal `ConfigInvalidError` (the schema indexes the string char-by-char: `Expected PermissionAction, got "a"`), which blocks startup. Setting every category to `allow` matches every tool/pattern so opencode never prompts. opencode's own `--dangerously-skip-permissions` flag exists only on the `run` subcommand (one-shot mode) and is rejected by the default TUI command's strict yargs parser, so the env-var path is the universal bypass.
- `cx` (codex) sets `IS_SANDBOX=1` and passes `--dangerously-bypass-approvals-and-sandbox`, codex's documented escape hatch that skips all confirmation prompts and disables codex's own command sandbox. The outer microvm provides the actual sandbox.
- `h` (hermes-agent) sets `HERMES_YOLO_MODE=1`, which bypasses hermes's dangerous-command approval prompts. The env var is equivalent to the `--yolo` flag but covers every subcommand (chat, gateway, cron). Hermes's hardline blocklist (`rm -rf /`, fork bombs, disk formatting) stays active regardless -- it is a code-level constant, not a prompt.
- `p` (pi) needs no flag or env var: pi has no built-in permission system at all (documented upstream), so it never prompts. The outer microvm is the only containment, same as the other harnesses.

## Adding a new harness

The architecture is harness-agnostic. Adding one means declaring its host paths (config/auth/data, each with a kind: `overlay`, `fw_cfg`, or `ephemeral`), launcher, and package in the `mkHarnesses` attrset in `flake.nix`, plus mirroring the harness name in the `HARNESSES` array in `cogbox-launch.sh` (the two lists must agree on names, which double as 9p tags, fw_cfg keys, and runtime symlink names).
