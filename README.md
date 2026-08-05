<h1 align="center">
  <img src="cogbox-icon.svg" width="120" alt=""><br>
  cogbox
</h1>

<p align="center">
  A NixOS <a href="https://github.com/microvm-nix/microvm.nix">microvm</a> sandbox for running coding-agent harnesses with permission prompts disabled.
</p>

Each harness's host config and auth tokens are mounted into an isolated
QEMU guest where the agent can read, write, and run commands without
prompting -- without that blast radius reaching the host.

Currently supported harnesses: `claude-code`
([Claude Code](https://docs.anthropic.com/en/docs/claude-code)),
`opencode` ([opencode](https://github.com/sst/opencode)),
`codex` ([OpenAI Codex CLI](https://github.com/openai/codex)),
`hermes-agent` ([Hermes Agent](https://github.com/NousResearch/hermes-agent)),
and `pi` ([pi coding agent](https://github.com/earendil-works/pi)). Codex is
opt-in and **disabled by default** (its Rust build is slow); enable it by
setting `enableCodex = true` in `flake.nix`. The architecture is
harness-agnostic; see [Harnesses](docs/harnesses.md) for the model and
how to add more.

## Quick start

```
nix run github:illustris/cogbox
```

On first run, the wrapper asks which harnesses to set up (only the ones
you pick get host-side config dirs created) and then prompts before
touching anything (the list reflects which harnesses were built in, so
`codex` appears only when `enableCodex` is on):

```
No harness state detected. Set up which?
  [1] claude-code     (creates ~/.claude/, ~/.claude.json)
  [2] hermes-agent     (creates ~/.hermes/)
  [3] opencode     (creates ~/.config/opencode/, ~/.local/share/opencode/)
  [4] pi     (creates ~/.pi/)
  [5] all
Choice [1-5, comma-separated for multiple]:

The following paths will be created:
  ~/.config/cogbox/instances/default/config.json  (default settings)
  ~/.config/cogbox/authorized_keys  (SSH public keys; seeded from ~/.ssh/*.pub + ssh-add -L)
  ~/.local/share/cogbox/cogbox_ed25519  (cogbox's own SSH key, the default identity for `cogbox ssh`)
  ~/.local/share/cogbox/instances/default/  (VM data)
  ...

Continue? [y/N]
```

The VM then starts in the background and, by default, `cogbox` waits for
the guest's SSH server to come up and drops you straight into an SSH
session. When you exit the session the VM keeps running (stop it with
`cogbox stop`). Pass `--no-ssh` to just start it and return, or `-f` to
watch it boot on the serial console instead (`Ctrl-]` detaches without
stopping the VM).

The package installs the CLI as both `cogbox` and `cbx` (a short alias
symlink); once it's on your `PATH`, the two names are interchangeable
(`cbx stop`, `cbx list`, ...).

Each enabled harness ships a launcher inside the VM: `c` for
`claude-code`, `oc` for `opencode`, `cx` for `codex`, `h` for
`hermes-agent`, `p` for `pi`. Every enabled harness binary is installed
regardless of which host-state directories you select, so once the VM
boots its launcher is on `$PATH`.

## Documentation

| Doc | Contents |
|---|---|
| [Network filtering](docs/network-filtering.md) | Network modes; L4 CIDR rules; TCP destination remap (SOCKS5); L7 vhost filtering with terminate/passthrough tiers and path constraints; threat model and enforcement internals |
| [Per-instance extensions](docs/extensions.md) | Extending one instance's NixOS config through its `flake/flake.nix` |
| [Plugins](docs/plugins.md) | Installable, versioned extensions: the flake contract, pinning, plugin-supplied firewall rules, the generated composition flake |
| [Harnesses](docs/harnesses.md) | The harness model, per-harness full-auto wiring, adding a harness |
| [Internals](docs/internals.md) | Directory layout, runtime dir + 9p shares, fw_cfg injection, launch-time patching, re-exec mechanism, host path overrides |

## Named instances

Run multiple isolated VMs simultaneously, like Wine prefixes. Each named
instance gets its own data directory, overlay image, and network ports.

```sh
# Default instance (starts in the background, then SSHes in)
nix run github:illustris/cogbox

# Create and start a named instance
nix run github:illustris/cogbox -- --name work
nix run github:illustris/cogbox -- --name personal --vcpu 8 --mem 16384

# List all instances and their ports
nix run github:illustris/cogbox -- list
```

Ports are auto-assigned when an instance is first created (default starts
at SSH 2222 / HTTP 8080; each new instance increments by one), including a
per-instance L7 port triple (`l7PortBase`). Override by editing the
instance config. Those values are only kept disjoint among *your own*
instances; on a shared multi-user host another user's instance may already
hold them (passt and the L7 proxy bind the host's shared loopback). When that
happens, `cogbox start` slides each conflicting port/triple to the next free
one at launch and persists the new value back to the instance config.

Harness authentication and base config are shared across all instances;
each instance overlays its own changes on top, so per-instance harness
settings persist independently (see [Harnesses](docs/harnesses.md)).

The guest's hostname is `cogbox-<instance>` (e.g. `cogbox-work`), and
interactive shells start in `~/work` (a symlink into the persisted host-shared
data dir), the standardized project workdir where plugin kits are materialized.

## CLI

cogbox uses a verb-based CLI. Bare `cogbox` (no verb) is sugar for
`cogbox start`. The VM always runs as a background daemon; its serial
console and QEMU monitor live on per-instance Unix sockets, so you can
attach and detach (`Ctrl-]`) freely without stopping the VM.

| Verb | Description |
|---|---|
| `start` | Init if needed, launch in the background, then SSH in (default verb). `--no-ssh` just returns; `-f` attaches the serial console. |
| `console` | Attach the serial console of a running instance (`Ctrl-]` detaches) |
| `monitor` | Attach the QEMU (HMP) monitor of a running instance |
| `stop` | Stop a running instance (SIGTERM, then SIGKILL with `--force`) |
| `restart` | `stop` then `start` |
| `status` | Print whether an instance is running, plus ports/net mode |
| `list` | List all instances. `--json` for machine-readable output |
| `init` | Create config + host directories without launching |
| `delete` | Delete an instance's config + persistent files (refuses if running; `-y` skips the prompt) |
| `ssh` | Connect to a running instance via SSH. A trailing command of two or more words is an argv vector: each word is quoted, so `#`, spaces, quotes, `$`, backticks and newlines reach the remote command literally. A command passed as ONE argument stays a shell string the guest shell interprets |
| `rules` | Manage CIDR (L4) allow/deny rules -- [docs](docs/network-filtering.md#l4-cidr-rules) |
| `remap` | Manage TCP destination-remap rules -- [docs](docs/network-filtering.md#tcp-destination-remap) |
| `l7` | Manage L7 (vhost) allow/deny rules -- [docs](docs/network-filtering.md#l7-host-filtering) |
| `plugin` | Manage guest plugins -- [docs](docs/plugins.md) |
| `help` | `cogbox help VERB` ≡ `cogbox VERB --help` |

Run `cogbox VERB --help` for verb-specific options.

### Common options

| Flag | Verbs | Description |
|---|---|---|
| `-n, --name NAME` | every verb that takes an instance | Instance name (default: `default`) |
| `-h, --help` | every verb | Show help and exit |
| `--no-ssh` | `start` | Don't auto-SSH after launch; start in the background and return |
| `-f, --foreground` | `start` | Attach the serial console after launch instead of SSHing |
| `-y, --yes` | `start`, `init`, `plugin`, `delete` | Skip the harness-selection prompt on first init / plugin and delete confirmation prompts |
| `--vcpu N` | `start`, `init` | vCPU count (default: config.json or 16) |
| `--mem N` | `start`, `init` | RAM in MB (default: config.json or 32768) |
| `--network MODE` | `start`, `init` | `full`, `none`, or `rules` (default: rules) |
| `--no-auto-keys` | `start`, `init` | Leave `authorized_keys` empty instead of seeding, and skip generating cogbox's own SSH key |
| `--bind-addr ADDR` | `init` | Seed `bindAddr` (default `127.0.0.1`) |
| `--no-implicit-dns` | `init` | Seed `network.implicitDns = false`, so port 53 stops escaping the L4 rule walk. Rules mode only -- see [network filtering](docs/network-filtering.md) |
| `--self-addr CIDR` | `init` | Seed one `network.selfAddrs` entry (repeatable): an address of the enclosing host, added to the L7 proxy's non-overridable floor. Rules mode only |
| `--force` | `stop` | Send SIGKILL after 10s if SIGTERM doesn't exit the process |
| `--json` | `list` | Emit one JSON object per instance |

When an instance is first created, `--vcpu`, `--mem`, and `--network` are
saved to its `config.json`. On subsequent runs they override the config for
that run only.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 3 | `status`: instance is stopped |
| 64 | EX_USAGE: bad CLI args, unknown verb, unknown flag |
| 65 | EX_DATAERR: invalid CIDR, integer, name |
| 66 | EX_NOINPUT: missing config (instance never inited) |
| 70 | EX_SOFTWARE: internal/system error |
| 75 | EX_TEMPFAIL: already running, port collision |

### Examples

```sh
# Lifecycle
cogbox init --name work             # create without starting
cogbox --name work                  # start + SSH in
cogbox ssh --name work htop         # one-off remote command
cogbox ssh -- tmux ls -F '#{session_name}'   # words stay literal (argv form)
cogbox ssh -- sh -c 'ls /root/*'    # shell syntax: one string, or sh -c
cogbox status --name work
cogbox stop --name work
cogbox delete --name work            # remove its config + persistent files

# Console access
cogbox -f                           # start and watch it boot
cogbox console                      # attach the console later
cogbox monitor                      # QEMU monitor ((qemu) prompt)
```

## Network filtering

The default `rules` mode gives the sandbox working public internet while
blocking LAN, link-local, and cloud-metadata ranges. On top of that, L7
rules whitelist individual vhosts behind shared IPs, with TLS termination
for `Host`/path enforcement. Rule edits hot-reload into a running VM.

```sh
cogbox rules add allow 192.168.1.50/32 --at 8    # open one LAN host (position matters)
cogbox l7 add allow api.example.com              # one vhost, not its LB siblings
cogbox l7 add allow git.example.com --path /myorg/
nix run github:illustris/cogbox -- --network none   # or: no network at all
```

First match wins and position matters; L7 has two tiers (terminate
default, passthrough for cert-pinned clients) and several deliberate
caveats. For the OAuth harnesses, the terminate tier also injects the real
token host-side by default, so the long-lived credential stays out of the
sandbox and the guest carries only a stub. **Read
[network filtering](docs/network-filtering.md)** for rule semantics, the
L4/L7 composition table, [host-side credential
injection](docs/network-filtering.md#host-side-credential-injection), the
threat model, and the enforcement internals.

## Configuration

All settings are in `~/.config/cogbox/` (or `$XDG_CONFIG_HOME/cogbox/`),
one subdir per instance under `instances/<name>/`. Edit and restart the
VM -- no rebuild needed.

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
| `overlaySize` | string | `128M` | Persistent harness overlay image |
| `storeOverlaySize` | string | `16G` | Writable nix store tmpfs |
| `bindAddr` | string | `127.0.0.1` | Host bind address for port forwards |
| `network` | string/object | seeded `rules` | `"full"`, `"none"`, or `{"rules":[...]}` |
| `network.implicitDns` | bool | absent (`true`) | `false` drops the implicit port-53 allow for this instance |
| `network.selfAddrs` | array | absent | Enclosing-host addresses added to the L7 proxy's hard floor |
| `l7PortBase` | int | 18443 | Base of the instance's L7 loopback port triple |
| `plugins` | array | absent | Managed by `cogbox plugin` -- see [Plugins](docs/plugins.md) |

Only include the keys you want to change -- missing keys use the defaults.

### authorized_keys

SSH public keys, one per line. On first init the shared file
(`~/.config/cogbox/authorized_keys`) is seeded from `~/.ssh/*.pub` plus
any keys in the running ssh-agent; pass `--no-auto-keys` to keep it
empty. A per-instance `instances/<name>/authorized_keys` overrides the
shared file. Without SSH keys, the VM console is accessible directly
(root autologin is enabled).

In addition, cogbox manages its own keypair at
`~/.local/share/cogbox/cogbox_ed25519` and unions its public key into
every guest's `authorized_keys` at launch, so `cogbox ssh` connects out
of the box without relying on your personal keys. It pins ssh to this key
alone (`-i` plus `IdentitiesOnly=yes` and `IdentityAgent=none`), so your
agent and `~/.ssh` keys are not offered and no agent is contacted -- a
gpg-agent with ssh support can't stall or prompt on connect. The private
key stays on the host -- it lives beside, not inside, the per-instance
data mounted into a VM, and is reused across all instances. (Under
`--no-auto-keys`, where no cogbox key exists, `cogbox ssh` instead falls
back to your agent and `~/.ssh` keys.)

`--no-auto-keys` at first init skips generating this key and records the
opt-out (at `~/.config/cogbox/no-cogbox-key`), so a later plain `cogbox
start` won't silently re-create it -- the guest stays reachable only via
the console. To opt back in, remove that marker. To rotate the key,
delete `~/.local/share/cogbox/cogbox_ed25519*`; the next launch (without
`--no-auto-keys`) regenerates it.

### Extending the guest

Two mechanisms, both folding NixOS modules into the instance's VM:

- **[Per-instance flake](docs/extensions.md)** -- edit
  `instances/<name>/flake/flake.nix` to add packages, services, mounts;
  applied on the next start.
- **[Plugins](docs/plugins.md)** -- install versioned extensions from any
  flake URL, optionally with the firewall rules they need:

  ```sh
  cogbox plugin add github:myorg/myplugin?dir=flake
  cogbox plugin add 'github:org/observability#loki' -n work
  cogbox plugin update
  ```

Host-side data locations can be overridden with `COGBOX_*` environment
variables -- see [Internals](docs/internals.md#host-side-path-overrides).

## Defaults

| Resource | Value |
|---|---|
| vCPUs | 16 |
| RAM | 32 GB |
| Writable nix store | 16 GB tmpfs overlay |
| Harness overlay (shared) | 128 MB ext4 image, per-harness subdirs |
| SSH | 127.0.0.1:2222 -> 22 |
| HTTP | 127.0.0.1:8080 -> 8080 |
| Network | rules (private/bogon denied, public allowed) |
| Docker | enabled |

Pre-installed tools: core — `git`, `curl`, `jq`, `vim`, `ncdu`, `tmux`, `htop`, `nixfs`; search/files — `ripgrep`, `fd`, `bat`, `sd`; data wrangling — `yq-go`, `duckdb`, `miller`, `dasel`, `gron`, `datamash`, `jo`; HTTP/DNS/web — `xh`, `websocat`, `dnsutils`, `htmlq`, `pup`; shell glue — `moreutils` (plus `xargs -P` for parallelism).
Harness binaries (with launchers): `claude-code` (`c`), `hermes-agent`
(`h`), `opencode` (`oc`), and `pi` (`p`) on `x86_64-linux` and
`aarch64-linux` (sourced from `numtide/llm-agents.nix`). `codex` (`cx`)
is opt-in (see above) and built in only when `enableCodex` is set.
Architecture-conditional extras: `bpftrace` (x86_64, aarch64), `nix-mcp`
(where the `nix-mcp` flake publishes a build).

## GCE backend image

`gce/` builds cogbox's HOST half as a NixOS system that boots on Google Compute
Engine under nested virtualization, running the same microVM guest it runs
locally. It exists for a control plane that gives each sandbox its own VM
instead of its own pod; nothing in it changes the local or Kubernetes paths.

| Output | What it is |
|---|---|
| `nixosConfigurations.cogbox-x86_64-gce` | The host system. x86_64 only -- GCE nested virtualization is Intel-series only |
| `packages.x86_64-linux.gce-image` | `disk.raw` in the sparse gzipped tar `gcloud compute images create` imports |
| `apps.x86_64-linux.push-gce-image` | Stage in GCS + register the image in a family. Run it with the image-pipeline identity, never the control plane's credential |

Units, all root-owned:

| Unit | Job |
|---|---|
| `cogworx-state-disk.service` | Format `/dev/disk/by-id/google-cogworx-state` on first boot ONLY (`blkid` guard); an unconditional mkfs would destroy the L7 CA, the secret store and the VM host key on every resume |
| `cogworx-attr-scrub.service` | Delete the previous boot's readiness/host-key guest attributes. Retries forever, and is deliberately independent of the floor unit |
| `cogworx-floor.service` | Install the nftables floor, then verify it with seven live connect probes -- three of them against a listener the probe binds itself -- and refuse the boot if the self-address set is empty |
| `cogworx-supervisor.service` | The sandbox lifecycle. `Requires=` both of the above, so a failed floor or scrub can never yield a running sandbox |
| `cogworx-cogbox-log.service` | Tail the cogbox runtime log into the JOURNAL. It is a separate unit so that log can never reach serial, which on GCE is provider-retained |
| `cogworx-nix-gc.service`/`.timer` | Collect the in-VM store when the boot disk runs low |
| `cogworx-resolver-deadline.service` | Power a resolver VM off after its deadline, independently of the provider-side field |

The floor itself is three rules, all matching on `skuid`, and what each one
matches is load-bearing rather than incidental:

| Rule | Realized form |
|---|---|
| 1 | `meta skuid cogbox-passt ip daddr 169.254.0.0/16 drop` -- the whole link-local range, not an enumeration of the metadata API and the resolver that shares its address by default. The host half keeps that address: every metadata read on the boot path goes there, and so does its own DNS while `vpcResolver` is left at the default |
| 2 | `meta skuid 0-4294967294 ct direction original ip daddr <self> drop`, one rule per address: **opening** a flow to the VM's own non-loopback addresses is dropped from **every** uid -- with `meta skuid root ip daddr <self> tcp dport 2222-2237 accept` rendered ahead of it, because `cogbox ssh` (and Terminal) dial the passt forward bound at `bindAddr` |
| 3 | `meta skuid cogbox-passt ct direction original ip daddr 127.0.0.0/8 drop` (and its `::1` mirror) -- with `... ip daddr 127.0.0.1 tcp dport { <funnel targets> } accept` above it. The passt uid, and only it, may not open a flow to this machine's loopback except to the L7 remap funnel's own targets |

Rule 2's shape carries three requirements. It must not be *narrowed* to named uids: an
enumeration of the passt and proxy uids leaves the hostile code out of the rule
-- in-VM plugin builds run as `nixbld*` under the daemon, and passt creates its
forward listeners *before* it drops privileges, so those sockets are root-owned
no matter how the drop is spelled. The proxy uid matters for the relay path
specifically: it re-resolves an allowed vhost and opens the upstream socket
under its own uid, so a passt-only drop would leave a guest-triggered relay into
the enclosing VM.

It must carry a `skuid` expression, because a same-host connection holds the
VM's own address on *both* ends, so the return packets also match `daddr <self>`
-- and when nothing is listening that reply is a kernel RST with no owning
socket, for which `meta skuid` cannot be fetched, so nftables skips the rule and
the RST survives. A drop with no `skuid` match swallows it and breaks the very
connection the exception above just allowed.

And it must be scoped to `ct direction original`, because the `skuid` expression
covers only that socket-less case. Once passt is actually *listening*, the reply
is a SYN-ACK from a real socket, and its destination port is the client's
ephemeral port, which no `dport` accept can match -- so an unscoped range ate it
and would take `cogbox ssh`, Terminal, Console-over-ssh and the user SSH gateway
down. Direction rather than `ct state new`: scoping by state
would also let a flow that survived a floor reload keep running, which the
unscoped drop did not. The cost is that the VM's netns now runs conntrack.

Loopback is deliberately outside rule 2 so the L7 remap funnel keeps working,
and nothing on the trusted half needs the VM's own address -- passt *binds*
there, which an output drop does not affect, and the one dial that needs it is
the `cogbox ssh` exception. A guest is unaffected by the direction scoping: its
first packet is the one that opens the flow, the deny takes it, and a dropped
OUTPUT packet is never confirmed into conntrack, so no reply direction ever
exists for it to ride.

Rule 3 is loopback's own rule, and it is the **opposite shape** to rule 2 on
purpose. It stays scoped to the passt uid instead of covering every uid, because
loopback is where the trusted half talks to itself -- l7proxy dials the mitm hop,
mitmproxy dials its upstreams, sshd and the nix daemon are there -- so a range
would cut the enforcement stack rather than protect it. passt is the only process
on the VM that turns guest bytes into host sockets, and its per-flow outbound
sockets are created *after* the privilege drop, so it is both the necessary and
the sufficient selector. The exception admits the funnel's own targets, which the
shim rewrites guest 443/80 to (`127.0.0.1:<l7base>` and `+1`, for each of the
triples cogbox may slide onto), as an explicit port **set**: the third port of
every triple is the mitmproxy SOCKS5 hop, which l7proxy dials under the *proxy*
uid, and a `dport <lo>-<hi>` range would hand it to the guest. `ct direction
original` is needed here for rule 2's reason -- the funnel's SYN-ACK carries
`daddr 127.0.0.1` and the client's ephemeral port, so a stateless deny would eat
every funnel reply.

What rule 3 backs up is worth stating, because the property does not rest on it
alone and never did. passt gives the guest the host interface's **own** address
over DHCP ("its own address shadows that of the host", `passt(1)`), so ordinary
guest traffic to the VM's address is delivered inside the guest and never reaches
the wire; a guest that *crafts* a frame to that address reaches passt, which
opens a real socket, and rule 2 takes it; a crafted frame carrying a loopback
address is dropped by passt on tap ingress; and `--no-map-gw` removes the
gateway-to-loopback mapping that would otherwise turn an address the guest can
name into `127.0.0.1` on the host. Rule 3 exists because the loopback half of
that list otherwise depends on upstream behavior. Rule 3 adds an independent
enforcement layer behind it.

One consequence for anyone testing this: **an in-guest probe of the VM's own
address proves nothing either way.** A connect to `<self>:22` from inside the
guest reaches the *guest's* sshd, and since both halves run the same nixpkgs
OpenSSH the banner is byte-identical to the host's, while rule 2's counter
correctly stays still because nothing was ever sent. Probe the SSH host key, or a
port only the host binds.

The control plane drives a booted image entirely through instance metadata; the
guest agent's metadata handling is disabled, so none of these keys can execute
code or install a login key.

| Metadata key | Read by |
|---|---|
| `cogworx-start-nonce` | supervisor, once per boot; stamped onto every guest attribute it publishes |
| `cogworx-instance` | supervisor (`cogbox init -n`), cogbox-log |
| `cogworx-vcpu`, `cogworx-mem-mb`, `cogworx-network` | supervisor sizing/mode |
| `cogworx-guest-resolver` | supervisor -> `COGBOX_GUEST_RESOLVER` (passt `--dns-forward` + `--no-map-gw`). A handle, not a destination: passt intercepts the guest's queries to it and re-emits them to the VM's own loopback forwarder (`COGBOX_HOST_RESOLVER`), so the guest resolves what the host resolves |
| `cogworx-self-addrs` | floor unit (rule 2) and supervisor (`--bind-addr`/`--self-addr`). Absent or empty falls back to the metadata server's own `instance/network-interfaces/*/ip`, because every insert body stamps this key empty (no address exists yet) and only a later Start refreshes it; an empty set from BOTH sources FAILS the boot in both |
| `cogworx-maintenance`, `cogworx-resolver` | supervisor short-circuit; read by key PRESENCE, never value |
| `cogworx-resolver-deadline` | resolver self-destruct timer |
| `cogworx-ssh-ca-pub`, `cogworx-ssh-principal` | supervisor: the gateway user CA staged for the guest, and the control certificate principal sshd accepts |

Guest attributes published back, both stamped `<nonce> <payload>`:
`cogworx/vm-host-key` (every boot class, before any sandbox start) and
`cogworx/ready` (level-held; deleted when the sandbox stops).

Two things the image cannot supply and the operator must:
`cogworx.gce.controlCAPublicKey` (empty means sshd trusts no control CA and
nothing can log in), and a state disk attached with the fixed `deviceName`
`cogworx-state`.

`packages.gce-image` builds the DEFAULT host config, whose
`controlCAPublicKey` is empty -- fail-closed, and therefore not publishable.
Bake a real image through the `lib.mkGceHost` seam instead:

```
nix build --impure --expr '((builtins.getFlake "/path/to/cc-sandbox").lib.mkGceHost
  "x86_64-linux" { extraModules = [ { cogworx.gce.controlCAPublicKey = "ssh-ed25519 AAAA... control-ca"; } ]; }
).config.system.build.googleComputeImage'
```

`nixosModules.gce-host` exports the host module itself for anyone composing
their own `nixosSystem`. The `gce-image-control-ca` flake check asserts both
halves: that the default bakes no CA, and that the override reaches sshd's
`TrustedUserCAKeys` file.

### The DNS upstream, and why the metadata server is not resolved

`cogworx.gce.vpcResolver` is the single upstream systemd-resolved forwards to,
authoritative for every name with an empty `FallbackDNS` behind it -- so it must
be a full recursive resolver, not a split-horizon forwarder for internal zones.
It defaults to GCE's VPC resolver (which *is* the metadata address), but another
full recursive resolver is also supported. Only the *default* is link-local:
with another resolver, floor rule 1
no longer covers a guest that dials the resolver itself, and that traffic is
ordinary private-range egress governed by the L4 shim and the instance's network
rules like any other. Rule 1's own invariant does not move either way -- the
metadata address stays link-local and stays denied to the guest wholesale.

Because of that, `/etc/hosts` pins `metadata.google.internal` to
`169.254.169.254` unconditionally. Every unit on the boot path (host-key
publish, readiness, the control-certificate principal, the floor's first-boot
address fallback, the attribute scrub) reaches the metadata server by name, so
without the pin a resolver that does not serve that GCE-internal name would
block metadata access. With it, the boot and control path
touches no resolver at all. `gce-image-metadata-pin` asserts the realized
`/etc/hosts` and refuses a resolved configured not to read it.

Leaving the default in place and *choosing* it are indistinguishable in the built
image, so a **publishable** bake has to say which it means: a config that sets
`cogworx.gce.controlCAPublicKey` -- the publishability gate, since a CA-less image
can authenticate no control connection -- while `vpcResolver` still names the VPC
resolver fails to evaluate unless it also sets
`cogworx.gce.allowMetadataResolver = true`. That is not a ban on the default; it
is an acknowledgement, and it exists because the address of a full recursive
resolver comes from an operator-side module: a bake composed without that module
falls back to the default silently, and every sandbox from the published image
then resolves neither internal names nor peering-shadowed public ones, with
nothing failing loudly. The guard is an assertion in the host module rather than a
flake check, for the same reason the control-PAM one is: it has to travel into an
operator's composed build, and an assertion in the operator module would disappear
together with the module whose absence is the bug. `gce-image-resolver-bake`
asserts that it fires, that both documented ways out satisfy it, and that the
CA-less default host still evaluates.

### Composing additional modules

`lib.mkGceHost` accepts `extraModules`. Security-sensitive SSH options are
intentionally constrained by the host module; use
`cogworx.gce.extraTrustedUserCAKeys` to add trusted user CAs. A composed module
that also defines `nix.registry.nixpkgs` must resolve that option conflict
explicitly.

## Limitations

- Linux host with KVM. Build targets: `x86_64-linux`, `aarch64-linux`,
  `riscv64-linux`.
- Per-harness platform availability varies. `claude-code`, `opencode`,
  `codex`, `hermes-agent`, and `pi` all come from
  `numtide/llm-agents.nix`, which builds them for `x86_64-linux` and
  `aarch64-linux` only.
- One instance per name at a time (PID lock per runtime directory).
  Multiple differently-named instances can run simultaneously.
- The writable nix store overlay is a tmpfs -- installed packages do not
  persist across VM reboots (but see
  [pre-populating the store](docs/extensions.md#example-pre-populate-the-nix-store-with-build-deps)).
- Changing `overlaySize` only affects newly created overlay images; delete
  the overlay image to recreate with a new size.
- Network `rules` mode filters at the passt syscall level; traffic
  handled internally by passt (ARP, DHCP, gateway ping responses) is not
  subject to user rules. See
  [enforcement internals](docs/network-filtering.md#enforcement-internals).
