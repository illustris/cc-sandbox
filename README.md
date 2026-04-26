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
| `--network MODE` | Network mode: `full`, `none`, or `rules` (default: config or rules) |
| `--init-only` | Run all setup steps but do not start the VM |
| `--list` | List all instances with their ports and status |
| `--help` | Show usage information |

When an instance is first created, `--vcpu`, `--mem`, and `--network` are
saved to its `config.json`. On subsequent runs they override the config for
that run only.

### Rules subcommand

| Subcommand | Description |
|---|---|
| `rules list [--name NAME]` | List current rules with 1-based indices |
| `rules add allow\|deny CIDR [--at N] [--name NAME]` | Add a rule (append, or insert at position N) |
| `rules del INDEX [--name NAME]` | Delete a rule by index |
| `rules set [--name NAME]` | Replace all rules from stdin |

If the instance is running, rule changes take effect immediately (the
runtime rules file is regenerated and passt receives `SIGUSR1` to reload).

```sh
# Prepare runtime directory without booting
nix run github:illustris/cc-sandbox -- --init-only

# Launch with 8 cores and 16 GB RAM
nix run github:illustris/cc-sandbox -- --vcpu 8 --mem 16384

# Create a named instance without starting it
nix run github:illustris/cc-sandbox -- --name work --init-only

# Launch with no outbound network
nix run github:illustris/cc-sandbox -- --network none

# Init with rules mode, then add rules
nix run github:illustris/cc-sandbox -- --name secure --network rules --init-only
cc-sandbox rules add deny 10.0.0.0/8 --name secure
cc-sandbox rules add allow 0.0.0.0/0 --name secure
```

## Network modes

Three modes are available. `full` and `rules` use
[passt](https://passt.top/) for networking, which supports all IP protocols
including ICMP. `none` uses QEMU's built-in SLIRP with `restrict=on`.

### full

Unrestricted networking via passt. All IP protocols (TCP, UDP, ICMP, etc.)
work. No extra privileges needed.

### none

QEMU's SLIRP `restrict=on` blocks all outbound traffic from the guest.
SSH and HTTP port forwards from the host still work. No extra privileges
needed.

Note: Claude Code requires access to the Anthropic API. In `none` mode,
Claude Code will not function unless API access is provided through another
channel (e.g., SSH port forwarding).

### rules (default)

Ordered CIDR allow/deny rules enforced via an LD_PRELOAD filter on
[passt](https://passt.top/). First match wins; default policy is deny.
No extra privileges needed. All IP protocols (TCP, UDP, ICMP) are
subject to the rules.

A new instance is seeded with deny rules for private (RFC1918), link-local
(including cloud metadata `169.254.169.254`), and bogon ranges, followed
by `allow 0.0.0.0/0` for the public internet. Net effect: working internet
out of the box, with LAN and metadata services blocked. Rule objects may
optionally carry a `comment` field; it's preserved through edits and
shown by `rules list` but ignored by the filter.

```json
{
    "network": {
        "rules": [
            {"deny":  "0.0.0.0/8",       "comment": "this network (RFC 1122)"},
            {"deny":  "10.0.0.0/8",      "comment": "RFC1918 private"},
            {"deny":  "100.64.0.0/10",   "comment": "carrier-grade NAT (RFC 6598)"},
            {"deny":  "169.254.0.0/16",  "comment": "link-local incl. cloud metadata 169.254.169.254"},
            {"deny":  "172.16.0.0/12",   "comment": "RFC1918 private"},
            {"deny":  "192.0.0.0/24",    "comment": "IETF protocol assignments (RFC 6890)"},
            {"deny":  "192.0.2.0/24",    "comment": "TEST-NET-1 documentation (RFC 5737)"},
            {"deny":  "192.168.0.0/16",  "comment": "RFC1918 private"},
            {"deny":  "198.18.0.0/15",   "comment": "benchmark testing (RFC 2544)"},
            {"deny":  "198.51.100.0/24", "comment": "TEST-NET-2 documentation (RFC 5737)"},
            {"deny":  "203.0.113.0/24",  "comment": "TEST-NET-3 documentation (RFC 5737)"},
            {"deny":  "224.0.0.0/4",     "comment": "multicast (RFC 5771)"},
            {"deny":  "240.0.0.0/4",     "comment": "reserved/broadcast incl. 255.255.255.255"},
            {"allow": "0.0.0.0/0",       "comment": "public internet"}
        ]
    }
}
```

To poke a hole for a specific LAN host, insert a more-specific allow
ahead of the matching deny:

```sh
# Allow the NAS at 192.168.1.50 while keeping the rest of 192.168/16 denied
cc-sandbox rules add allow 192.168.1.50/32 --at 8
```

Rules can be managed dynamically (updates take effect immediately on
running instances via SIGUSR1):

```sh
cc-sandbox rules list
cc-sandbox rules add deny 8.8.8.8/32 --at 1
cc-sandbox rules del 1
```

Implicit rules (applied before user rules, not configurable):
- **DNS (port 53)** is always allowed so hostname resolution works
- **Loopback (127.0.0.0/8, ::1)** is always denied to prevent the VM
  from accessing host services via passt's gateway-to-loopback mapping

The filter works by intercepting passt's outbound `connect()`,
`sendto()`, `sendmsg()`, and `sendmmsg()` syscalls. Since passt is the
VM's only network path, this is a complete enforcement point. The filter
is a Zig shared library (`libnetfilter.so`) loaded via `LD_PRELOAD`;
initialization runs before passt enables its seccomp sandbox.

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
    "network": {"rules": [...]}
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
| `network` | string/object | seeded `rules` | Network mode: `"full"`, `"none"`, or `{"rules":[...]}` |

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

In `rules` network mode, the wrapper loads a Zig shared library
(`libnetfilter.so`) into passt via `LD_PRELOAD`. The library intercepts
outbound socket calls (`connect`, `sendto`, `sendmsg`, `sendmmsg`) and
checks destination addresses against the configured CIDR rules. Denied
connections receive `ENETUNREACH`. The library initializes via
`.init_array` (before `main()`) so that all file I/O for rule loading
completes before passt activates its seccomp-bpf sandbox. Rules can be
hot-reloaded at runtime via `SIGUSR1` to the passt process.

## Defaults

| Resource | Value |
|---|---|
| vCPUs | 16 |
| RAM | 32 GB |
| Writable nix store | 16 GB tmpfs overlay |
| Claude config overlay | 128 MB ext4 image |
| SSH | 127.0.0.1:2222 -> 22 |
| HTTP | 127.0.0.1:8080 -> 8080 |
| Network | rules (private/bogon denied, public allowed) |
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
- Network `rules` mode filters at the passt syscall level; traffic
  handled internally by passt (ARP, DHCP, gateway ping responses) is not
  subject to user rules. The implicit loopback deny prevents access to
  host services via the passt gateway.
