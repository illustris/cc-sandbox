# cc-sandbox

A NixOS [microvm](https://github.com/microvm-nix/microvm.nix) for running
[Claude Code](https://docs.anthropic.com/en/docs/claude-code) in an isolated
QEMU sandbox with `--dangerously-skip-permissions`.

## Quick start

```
nix run github:illustris/cc-sandbox
```

On first run, the wrapper creates a config directory and prompts before
touching anything:

```
The following paths will be created:
  ~/.config/cc-sandbox/config.json  (default settings)
  ~/.config/cc-sandbox/authorized_keys  (SSH public keys, empty)
  ~/.local/share/cc-sandbox/  (VM data)
  ~/.claude/  (Claude config)
  ~/.claude.json  (Claude auth)

Continue? [y/N]
```

Once the VM boots, run `c` to launch Claude Code.

## Named instances

Run multiple isolated VMs simultaneously, like Wine prefixes. Each named
instance gets its own data directory, overlay image, and network ports.

```sh
# Default instance (unchanged behavior)
nix run github:illustris/cc-sandbox

# Create and start a named instance
nix run github:illustris/cc-sandbox -- --name work
nix run github:illustris/cc-sandbox -- --name personal --vcpu 8 --mem 16384

# List all instances and their ports
nix run github:illustris/cc-sandbox -- --list
```

Ports are auto-assigned when an instance is first created (default starts
at SSH 2222 / HTTP 8080; each new instance increments by one). You can
override ports by editing the instance config.

Claude authentication (`~/.claude.json`) and base Claude config (`~/.claude/`)
are shared across all instances. Each instance gets its own overlay on
top of the shared config, so per-instance Claude settings persist
independently.

## Flags

| Flag | Description |
|---|---|
| `--name NAME` | Use a named instance (creates it on first run) |
| `--vcpu N` | Set vCPU count (default: config.json or 16) |
| `--mem N` | Set RAM in megabytes (default: config.json or 32768) |
| `--network MODE` | Network mode: `full` or `none` (default: config or full) |
| `--init-only` | Run all setup steps but do not start the VM |
| `--list` | List all instances with their ports and status |
| `--help` | Show usage information |

When an instance is first created, `--vcpu`, `--mem`, and `--network` are
saved to its `config.json`. On subsequent runs they override the config for
that run only.

```sh
# Prepare runtime directory without booting
nix run github:illustris/cc-sandbox -- --init-only

# Launch with 8 cores and 16 GB RAM
nix run github:illustris/cc-sandbox -- --vcpu 8 --mem 16384

# Create a named instance without starting it
nix run github:illustris/cc-sandbox -- --name work --init-only

# Launch with no outbound network
nix run github:illustris/cc-sandbox -- --network none
```

## Network modes

By default the VM has unrestricted network access through QEMU's user-mode
(SLIRP) networking. Three modes are available:

### full (default)

Unrestricted networking. No extra privileges needed.

### none

QEMU's `restrict=on` blocks all outbound traffic from the guest. SSH and
HTTP port forwards from the host still work. No extra privileges needed.

Note: Claude Code requires access to the Anthropic API. In `none` mode,
Claude Code will not function unless API access is provided through another
channel (e.g., SSH port forwarding).

### rules

Ordered CIDR allow/deny rules enforced via nftables inside a Linux network
namespace. First match wins; default policy is deny. Requires `sudo`.

```json
{
    "network": {
        "rules": [
            {"allow": "10.0.1.0/24"},
            {"deny": "10.0.0.0/8"},
            {"allow": "0.0.0.0/0"}
        ]
    }
}
```

```sh
sudo nix run github:illustris/cc-sandbox
```

DNS (port 53) is always allowed before user rules so hostname resolution
works. Loopback traffic and established connections are also always
allowed.

The rules are enforced at the host level via a network namespace -- they
cannot be modified or bypassed from inside the VM. The wrapper creates
a veth pair, NATs traffic through the host, and runs QEMU inside the
namespace. Port forwards are bridged from the host to the namespace via
socat, so `ssh -p 2222 root@localhost` works as usual.

To allow Claude Code while blocking internal networks, use a catch-all
allow with specific deny rules:

```json
{
    "network": {
        "rules": [
            {"deny": "10.0.0.0/8"},
            {"deny": "172.16.0.0/12"},
            {"deny": "192.168.0.0/16"},
            {"allow": "0.0.0.0/0"}
        ]
    }
}
```

## Configuration

All settings are in `~/.config/cc-sandbox/` (or `$XDG_CONFIG_HOME/cc-sandbox/`).
Edit them and restart the VM -- no rebuild needed.

### config.json

```json
{
    "vcpu": 16,
    "mem": 32768,
    "sshPort": 2222,
    "httpPort": 8080,
    "overlaySize": "128M",
    "storeOverlaySize": "16G",
    "bindAddr": "127.0.0.1",
    "network": "full"
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `vcpu` | int | 16 | Virtual CPUs |
| `mem` | int | 32768 | RAM in megabytes |
| `sshPort` | int | 2222 | Host port forwarded to guest SSH (22) |
| `httpPort` | int | 8080 | Host port forwarded to guest 8080 |
| `overlaySize` | string | `128M` | Persistent Claude config overlay image |
| `storeOverlaySize` | string | `16G` | Writable nix store tmpfs |
| `bindAddr` | string | `127.0.0.1` | Host bind address for port forwards |
| `network` | string/object | `"full"` | Network mode: `"full"`, `"none"`, or `{"rules":[...]}` |

Only include the keys you want to change -- missing keys use the defaults.

### Per-instance configuration

Named instances store their config under `~/.config/cc-sandbox/instances/<name>/`:

```
~/.config/cc-sandbox/
  config.json                  # default instance
  authorized_keys              # shared SSH keys
  instances/
    work/
      config.json              # auto-generated with unique ports
      authorized_keys          # optional per-instance SSH keys
    personal/
      config.json
```

Each instance config has the same format as the default `config.json`.
SSH keys fall back to the shared `authorized_keys` unless a per-instance
file exists.

Data (VM state, overlays) is stored per-instance under
`~/.local/share/cc-sandbox/instances/<name>/`.

### authorized_keys

SSH public keys, one per line (same format as `~/.ssh/authorized_keys`).
Empty by default. The VM loads these at boot from the shared data directory.

```sh
# Enable SSH access
cp ~/.ssh/id_ed25519.pub ~/.config/cc-sandbox/authorized_keys
ssh -p 2222 root@localhost
```

Without SSH keys, the VM console is accessible directly in the terminal
(root autologin is enabled).

### Host-side paths

Override where data lives on the host with environment variables:

| Variable | Default | Description |
|---|---|---|
| `CC_SANDBOX_DATA` | `$HOME/.local/share/cc-sandbox` | Persistent data volume |
| `CC_SANDBOX_CLAUDE_CONFIG` | `$HOME/.claude` | Host Claude config (read-only in VM) |
| `CC_SANDBOX_CLAUDE_AUTH` | `$HOME/.claude.json` | Auth token for the VM |

```sh
CC_SANDBOX_DATA=/mnt/fast/cc-sandbox nix run .
```

## How it works

QEMU's 9p share sources must be absolute paths known at build time. The
wrapper creates a symlink directory at `/tmp/cc-sandbox/` pointing to the
user's actual paths, so the built VM image works for any user:

```
/tmp/cc-sandbox/
  data/            -> $CC_SANDBOX_DATA
  claude-config/   -> $CC_SANDBOX_CLAUDE_CONFIG
  claude-auth.json -> $CC_SANDBOX_CLAUDE_AUTH
```

Runtime settings (vcpu, memory, ports) are applied by patching the microvm
runner script's QEMU arguments at launch time. Settings that affect the
guest (overlay sizes, SSH keys) are written to the shared data directory
where systemd services inside the VM pick them up at boot.

Named instances use separate runtime directories (`/tmp/cc-sandbox-<name>/`),
each with its own symlinks and PID lock. The wrapper patches the QEMU
runner's 9p share source paths to point at the instance-specific runtime
directory, so the same VM image serves all instances.

In `rules` network mode, the wrapper creates a Linux network namespace,
connects it to the host via a veth pair with NAT, and applies nftables
rules inside the namespace. QEMU runs inside the namespace; socat bridges
port forwards from the host to the namespace IP.

## Defaults

| Resource | Value |
|---|---|
| vCPUs | 16 |
| RAM | 32 GB |
| Writable nix store | 16 GB tmpfs overlay |
| Claude config overlay | 128 MB ext4 image |
| SSH | 127.0.0.1:2222 -> 22 |
| HTTP | 127.0.0.1:8080 -> 8080 |
| Network | full (unrestricted) |
| Docker | enabled |

Pre-installed tools: `claude-code`, `git`, `curl`, `jq`, `vim`, `ncdu`,
`tmux`, `htop`, `bpftrace`, `nix-mcp`, `nixfs`.

## Limitations

- x86_64-linux only (QEMU with KVM)
- One instance per name at a time (PID lock per runtime directory).
  Multiple differently-named instances can run simultaneously.
- The writable nix store overlay is a tmpfs -- installed packages do not
  persist across VM reboots
- Changing `overlaySize` only affects newly created overlay images; delete
  the overlay image to recreate with a new size
- Network `rules` mode requires `sudo` for namespace and nftables setup
