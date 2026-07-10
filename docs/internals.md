# Internals

How cogbox wires a per-user, per-instance sandbox out of a single prebuilt VM image. Useful when debugging, or when extending cogbox itself.

## Directory layout

Each instance has its own config dir under `~/.config/cogbox/instances/<name>/`. The default instance uses the reserved name `default`, so the config layout mirrors the data layout:

```
~/.config/cogbox/
  authorized_keys              # shared SSH keys (fallback for all instances)
  instances/
    default/
      config.json              # default instance settings (sshPort 2222)
      flake/
        flake.nix              # per-instance NixOS extensions (no-op default)
      plugins-flake/
        flake.nix              # GENERATED plugin composition (only with plugins)
      l7-ca/                   # per-instance L7 terminate CA (key never leaves host)
    work/
      config.json              # auto-generated with unique ports
      flake/
        flake.nix
      authorized_keys          # optional per-instance SSH keys
```

SSH keys fall back to the shared top-level `authorized_keys` unless a per-instance file exists. At launch, cogbox's own public key (`~/.local/share/cogbox/cogbox_ed25519.pub`, see below) is unioned into whichever file is used, so `cogbox ssh` always has an authorized identity.

Data (VM state, overlays) is stored per-instance under `~/.local/share/cogbox/instances/<name>/`. All instances are siblings, so a default-instance boot does not 9p-share named-instance state into the default guest:

```
~/.local/share/cogbox/
  cogbox_ed25519             # cogbox's own SSH key; default identity for `cogbox ssh`
  cogbox_ed25519.pub         # its pubkey, unioned into each guest's authorized_keys
  instances/
    default/
      harness-overlay.img      # shared ext4 overlay for all harnesses
      .config/active-harnesses # newline-separated list of active harnesses
    work/
      harness-overlay.img
```

The keypair sits in the data-dir root, a sibling of `instances/`. Only `instances/<name>/` is 9p-mounted into a guest, so the private key never enters the sandbox. It is generated automatically and reused across all instances; generation is idempotent and re-runs on every launch, so an existing setup gains the key on upgrade and a deleted key is regenerated. `--no-auto-keys` at first init skips generation and writes a durable opt-out marker (`~/.config/cogbox/no-cogbox-key`) so a later plain launch does not re-create the key. The Zig `ssh` and `start` verbs pin ssh to it -- `ssh -i <data>/cogbox_ed25519 -o IdentitiesOnly=yes -o IdentityAgent=none` -- so the user's agent and `~/.ssh` keys are not offered and no agent is contacted (a gpg-agent can't stall or prompt on connect). Under `--no-auto-keys`, where the key is absent, ssh falls back to the user's agent and `~/.ssh` keys.

## Runtime directory and 9p shares

QEMU's 9p share sources must be absolute paths known at build time. The wrapper creates a per-instance symlink directory pointing to the user's actual paths, so the built VM image works for any user. Runtime state lives under `$XDG_RUNTIME_DIR/cogbox` (typically `/run/user/$UID/cogbox`); named instances append a `-<name>` suffix. Each has its own symlinks and PID lock:

```
$XDG_RUNTIME_DIR/cogbox[-<name>]/
  data/                  -> $COGBOX_DATA/instances/<name>
  claude-code-config     -> $COGBOX_CLAUDE_CONFIG
  claude-code-auth       -> $COGBOX_CLAUDE_AUTH
  opencode-config        -> $COGBOX_OPENCODE_CONFIG
  opencode-data          -> $COGBOX_OPENCODE_DATA
  codex-home             -> $COGBOX_CODEX_HOME
  hermes-agent-home      -> $COGBOX_HERMES_HOME
  pi-home                -> $COGBOX_PI_HOME
  .harness-stubs/        # empty stubs for inactive harnesses (so QEMU
                         # 9p sources resolve even when the host has no
                         # state for a given harness)
  console.sock           # guest serial console (Unix socket)
  monitor.sock           # QEMU HMP monitor (Unix socket)
  netfilter-rules        # rendered L4 + remap runtime rules
  l7-rules               # rendered L7 runtime rules
  console.log            # captured guest serial output
  cogbox.log             # daemon stdout/stderr (passt, QEMU warnings); kept on a failed start for post-mortem
```

If `$XDG_RUNTIME_DIR` is unset and `/run/user/$UID` doesn't exist (no active logind session), the wrapper falls back to `/tmp/cogbox-runtime-$UID/` per the XDG spec.

`cogbox delete [-n <name>]` removes all three of these per-instance trees -- the config dir, the data dir, and the runtime dir -- for one instance. It refuses while the instance is running (stop it first) and prompts before removing anything unless `-y` is given.

## Launch-time patching

Runtime settings (vcpu, memory, ports) are applied by patching the microvm runner script's QEMU arguments at launch time. Settings that affect the guest (overlay sizes, SSH keys) are written to the instance's data directory where systemd services inside the VM pick them up at boot. The wrapper patches the QEMU runner's 9p share source paths to point at the instance-specific runtime directory, so the same VM image serves all instances.

Single-file injections (harness auth tokens, the L7 CA certificate) go through QEMU's `fw_cfg` instead of 9p: the wrapper passes `-fw_cfg name=opt/<tag>,file=<source>` and a guest systemd service copies the blob out of `/sys/firmware/qemu_fw_cfg` at boot.

## Guest extension re-exec

Two sources of guest extension share one mechanism, `--override-input userExtensions`:

1. With [plugins](plugins.md) installed (`.plugins` non-empty in config.json), the wrapper re-execs `nix run` with `userExtensions` pointing at the generated `plugins-flake/`, which composes every plugin module plus the user flake.
2. Otherwise, if the [per-instance flake](extensions.md) differs from the scaffold, `userExtensions` points at `flake/` directly. A pristine scaffold skips the re-exec entirely (the closure would be identical to the baked-in one, and re-evaluating the cogbox flake needs its inputs fetchable).

`COGBOX_REEXECED` breaks the loop after one hop. Non-launch verbs never re-exec.

## Plugin brain materialization

The base module declares the `cogbox.*` option tree and folds the merged `config.cogbox` of every plugin into one `cogbox-brain` derivation at build (per-harness native trees + merged `opencode.json`/`.mcp.json`/codex `config.toml` + a generated capability index skill). Two base-owned `Type=oneshot` services (modeled on `load-ssh-keys`, ordered `before=sshd.service`) materialize it at boot:

1. `cogbox-brain-materialize` creates the `~/work` (`/root/work` → `/var/lib/cogbox/work`) symlink, the `~/work/.cogbox/brain` link to the RO store derivation, and per-leaf child symlinks into each harness's real writable dirs (`.claude/skills/<s>`, `.opencode/agents/<a>.md`, `.agents/skills/<s>`, …). It only ever drops *child* symlinks, never whole-dir links, so the harness can scaffold session state alongside and peers coexist. It reads only closure-resident store paths, so it works offline.
2. `cogbox-brain-trust` pre-accepts Claude Code workspace trust for `~/work` (both `/root/work` and the `/var/lib/cogbox/work` it resolves to) and reconciles stale pre-migration project keys.

The workdir/cwd is base-owned: `programs.bash.loginShellInit` and the harness launchers (`c`/`oc`/`cx`/`h`/`p`) `cd ~/work` (the launcher also exports `OPENCODE_CONFIG` and merges `cogbox.env`). The contract has no `loginShellInit`/`cwd` surface, so a plugin cannot fight over cwd. See [plugins](plugins.md) for the full contract.

## Guest environment and non-Nix binaries

The L7 CA-trust env (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …, all pointing at the assembled `/run/cogbox/ca-bundle.crt`) is set both as `environment.variables` (login shells) and `environment.sessionVariables`. The latter matters because the container sshd runs `UsePAM yes`, so `pam_env` delivers `sessionVariables` to *non-interactive* `ssh host cmd` execs — which source no login shell. That is the path VS Code Remote-SSH uses, so its server and tools see the CA bundle.

`programs.nix-ld` is enabled so downloaded, dynamically-linked non-Nix ELF binaries run in the otherwise pure-Nix guest. VS Code Remote-SSH ships a prebuilt glibc `node` (vscode-server) that expects a standard `/lib64/ld-linux` loader; nix-ld provides the `/lib64` stub loader and delivers `NIX_LD`/`NIX_LD_LIBRARY_PATH` via the same `sessionVariables`/`pam_env` mechanism. The stock library set is extended with `stdenv.cc.cc.lib`, `icu`, and `libsecret` for common VS Code extension native binaries.

## Network enforcement

In `rules` network mode, the wrapper loads a Zig shared library (`libnetfilter.so`) into passt via `LD_PRELOAD`. The library intercepts outbound socket calls (`connect`, `sendto`, `sendmsg`, `sendmmsg`) and checks destination addresses against the configured CIDR rules; denied connections receive `ENETUNREACH`. It initializes via `.init_array` (before `main()`) so all file I/O for rule loading completes before passt activates its seccomp-bpf sandbox. Rules hot-reload via `SIGUSR1`; the L7 proxy reloads via `SIGHUP`. Details, including the remap/SOCKS5 layer and the L7 proxy architecture, are in [network filtering](network-filtering.md).

The `cogbox rules`/`remap`/`l7`/`plugin` verbs all edit `config.json`, regenerate the runtime rules files, and signal the running processes, so policy changes take effect without restarting the VM. The CLI shares the on-disk rule format parser with the LD_PRELOAD filter, so the formats stay in sync.

## Host-side path overrides

Override where data lives on the host with environment variables:

| Variable | Default | Description |
|---|---|---|
| `COGBOX_DATA` | `$XDG_DATA_HOME/cogbox` (i.e. `~/.local/share/cogbox`) | Persistent data root. Each instance lives at `$COGBOX_DATA/instances/<name>/`. |
| `COGBOX_CLAUDE_CONFIG` | `$HOME/.claude` | Host claude-code config (overlay lower in VM) |
| `COGBOX_CLAUDE_AUTH` | `$HOME/.claude.json` | claude-code account/telemetry config (incl. the org UUID `/rc` needs), copied in via `fw_cfg`. Holds **no** secret token -- the OAuth tokens live in `COGBOX_CLAUDE_CONFIG`'s `.credentials.json` (overlay, redacted under injection) |
| `COGBOX_OPENCODE_CONFIG` | `$XDG_CONFIG_HOME/opencode` | Host opencode config (overlay lower in VM) |
| `COGBOX_OPENCODE_DATA` | `$XDG_DATA_HOME/opencode` | Host opencode data (auth lives here as `auth.json`) |
| `COGBOX_CODEX_HOME` | `$HOME/.codex` | Host codex home (config, auth, sessions; overlay lower in VM) |
| `COGBOX_HERMES_HOME` | `$HOME/.hermes` | Host hermes-agent home (config.yaml, `.env` credentials, skills; overlay lower in VM) |
| `COGBOX_PI_HOME` | `$HOME/.pi` | Host pi home (`agent/` holds auth.json, settings, sessions; overlay lower in VM) |

```sh
COGBOX_DATA=/mnt/fast/cogbox nix run .
```

## Running as another user (sudo context)

cogbox resolves the *real* (non-root) user -- whose `$HOME` holds the config, data, and harness credential files -- from `SUDO_USER`, but **only when actually running as root** (euid 0). That is the genuine `sudo cogbox` case, where cogbox acts on the invoking user's behalf and `chown`s the files it creates back to them. When not root, cogbox uses its own identity (`id` / `$HOME`).

This guard matters because `sudo` exports `SUDO_USER` for *every* invocation (including `sudo -u other`), and a non-login `su other` preserves it. So `sudo su <user>` **without** `-` leaves the invoker's `SUDO_USER`/`HOME` in the environment; without the euid guard cogbox would resolve paths to the *invoker*, not the user it now runs as, and write into a directory it can't touch. A fail-fast preflight catches this -- if the resolved home isn't writable by the current uid, cogbox aborts with actionable guidance instead of cascading permission errors.

**To run cogbox as a different user, use a login shell** -- `sudo su - <user>` (or `sudo -u <user> env -u SUDO_USER HOME=/home/<user> cogbox`) -- not `sudo su <user>`. This is the invocation a multi-user control plane must use to launch cogbox per-user.
