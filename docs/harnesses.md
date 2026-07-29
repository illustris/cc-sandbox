# Harnesses

A *harness* is a coding-agent CLI that cogbox installs in the guest and mounts host state for. The currently-supported harnesses are `claude-code` (launcher: `c`), `opencode` (launcher: `oc`), `codex` (launcher: `cx`), `hermes-agent` (launcher: `h`), and `pi` (launcher: `p`). Codex is opt-in and disabled by default (its Rust build is slow) -- set `enableCodex = true` in `flake.nix` to build it in. When a harness is not built in, its launcher, mounts, and host-state seeding are all omitted (the launcher's `HARNESSES` list is generated from the same `mkHarnesses` set).

## 2026-07 harness refresh

The shared `numtide/llm-agents.nix` input is pinned as one release unit so the VM and container images consume the same harness builds. The current pin updated claude-code `2.1.214` to `2.1.220`, opencode `1.18.3` to `1.18.7`, codex `0.144.5` to `0.145.0`, pi `0.80.10` to `0.82.1`, and hermes from source release `2026.7.7` (CLI `v0.18.1`) to `2026.7.20` (CLI `v0.19.0`) -- note hermes moves on both axes independently, so the CLI string in the release gate is not derivable from the package version and has to be read off the built binary. Codex is built and version-checked by the release gate but remains absent from default images while `enableCodex = false`.

The input deliberately does not set `inputs.nixpkgs.follows` (see the comment on it in `flake.nix`), because llm-agents publishes its builds to `cache.numtide.com` against its own pinned nixpkgs and overriding that would force a local rebuild of every harness. That holds for four of the five, but on this pin **hermes-agent is a source build** -- it compiles a bun2nix-based `hermes-frontend`, which can take roughly a quarter hour on a cold store. Bumping this input therefore is not reliably a lock-only change; budget for the rebuild.

Three upstream behaviours require local compatibility handling:

- `cogbox-brain-materialize` creates a `cron`, `sessions`, `logs`, `memories` skeleton under the Hermes home after persistent state is ready. `HERMES_MANAGED=nixos` is not set anywhere in this repo, so the skeleton is currently defensive rather than load-bearing. If that variable is enabled, the dependency needs its own validation. The VM requires the Hermes overlay mount before materialization; the container maps `/root/.hermes` to `/var/lib/cogbox-state/hermes-home` on the per-instance PVC. Container setup replaces only an empty image scaffold and fails closed on a nonempty directory, wrong symlink, or invalid persistent target rather than merging or deleting state.
- The updated pi package switched its installed executable from the npm/Node entrypoint to a Bun standalone. Cogbox retains pi source and version `0.82.1` but overrides the install phase to use the package's supported Node entrypoint, preserving the upstream `fd`/`ripgrep` helper path and telemetry/version-check settings. That override has not been validated against `0.82.1`: pi ships opt-out (`enablePi = false`), and the release gate version-checks the base numtide package. Anyone setting `enablePi = true` should confirm the Node entrypoint still exists upstream.
- Claude-code requires its first-run bypass-permissions consent before the `c` launcher can reach the REPL. Cogbox seeds the top-level `bypassPermissionsModeAccepted` key alongside `hasCompletedOnboarding` on both backends: the VM through `brainTrustScript`, and the container through both branches of `claudeStubScript`. Claude-code migrates the acceptance into `userSettings.skipDangerousModePermissionPrompt` and removes the top-level key on first run, so a used config without `bypassPermissionsModeAccepted` is expected. `checks.harness-firstrun-flags` asserts all three seed sites. Bare `claude` remains in manual mode.

The release gate executes all five package version paths, boots the full VM check, exercises Hermes managed-home initialization and overlay placement, verifies pi through `p --version`, and builds both harness-bearing OCI images from the same source tree.

## The harness model

The model is symmetric and opt-in:

- **All enabled harness binaries are always installed** in the guest, regardless of which host-state directories are active. Codex remains excluded unless enabled at build time.
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

Independently of the shared host config above, [plugins](plugins.md) contribute an agent-facing **kit** (skills/agents/commands/rules + merged MCP/settings) via the `cogbox.*` module options. The base materializes one neutral kit into each enabled harness's native layout under the project workdir `~/work` — `.claude/`, `.opencode/`, the `.agents/skills/` tree shared by codex and pi, hermes's `~/.hermes/skills/`, and a harness-neutral `AGENTS.md` rules digest (read by pi, hermes, and codex; linked only-if-absent) — so the same plugin serves every harness. pi/hermes gaps: no plugin MCP, settings, agent, or command mapping yet. Plugin *tools* reach every harness via the shared `PATH` prepend. This is project-scoped and per instance: Hermes's skill links land in the VM overlay upper or the container's PVC-backed Hermes home, not in shared host config. See [plugins.md](plugins.md#harness-agnostic--native-mapping) for the mapping table.

## How "full auto" is wired per harness

- `c` (claude-code) sets `IS_SANDBOX=1` and passes `--dangerously-skip-permissions`.
- `oc` (opencode) sets `OPENCODE_PERMISSION='{"edit":"allow","bash":"allow","webfetch":"allow","doom_loop":"allow","external_directory":"allow"}'`. Opencode `JSON.parse`s that env var and merges it into `config.permission`. Opencode 1.18.3 still requires the object form keyed by permission category (`edit`/`bash`/`webfetch`/`doom_loop`/`external_directory`, each `ask|allow|deny`; `bash` may also be a `{pattern: action}` map) -- the old bare-string shorthand `"allow"` is rejected with a fatal `ConfigInvalidError` (the schema indexes the string char-by-char: `Expected PermissionAction, got "a"`), which blocks startup. Setting every category to `allow` matches every tool/pattern so opencode never prompts. opencode's own `--dangerously-skip-permissions` flag exists only on the `run` subcommand (one-shot mode) and is rejected by the default TUI command's strict yargs parser, so the env-var path is the universal bypass.
- `cx` (codex) sets `IS_SANDBOX=1` and passes `--dangerously-bypass-approvals-and-sandbox`, codex's documented escape hatch that skips all confirmation prompts and disables codex's own command sandbox. The outer microvm provides the actual sandbox.
- `h` (hermes-agent) sets `HERMES_YOLO_MODE=1`, which bypasses hermes's dangerous-command approval prompts. The env var is equivalent to the `--yolo` flag but covers every subcommand (chat, gateway, cron). Hermes's hardline blocklist (`rm -rf /`, fork bombs, disk formatting) stays active regardless -- it is a code-level constant, not a prompt.
- `p` (pi) needs no flag or env var: pi has no built-in permission system at all (documented upstream), so it never prompts. The outer microvm is the only containment, same as the other harnesses.

## Adding a new harness

The architecture is harness-agnostic. Adding one means declaring its host paths (config/auth/data, each with a kind: `overlay`, `fw_cfg`, or `ephemeral`), launcher, and package in the `mkHarnesses` attrset in `flake.nix`, then adding the matching host-path metadata in `cogbox-launch.sh`. The launcher's `HARNESSES` list is generated from `mkHarnesses`; harness names double as 9p tags, fw_cfg keys, and runtime symlink names.
