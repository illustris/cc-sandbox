# Network filtering

cogbox restricts what the sandboxed agent can reach on the network. Filtering is layered: a network *mode* selects the overall posture, L4 CIDR rules filter by destination IP, a remap table can redirect TCP flows into a proxy, and L7 rules filter individual virtual hosts behind shared IPs. This document covers all of it, including the threat model and the enforcement internals.

- [Network modes](#network-modes)
- [L4 CIDR rules](#l4-cidr-rules)
- [TCP destination remap](#tcp-destination-remap)
- [L7 host filtering](#l7-host-filtering)
- [Host-side credential injection](#host-side-credential-injection)

## Network modes

Three modes are available. `full` and `rules` use [passt](https://passt.top/) for networking, which supports all IP protocols including ICMP. `none` uses QEMU's built-in SLIRP with `restrict=on`. None of them need extra privileges.

| Mode | Posture |
|---|---|
| `full` | Unrestricted networking via passt. All IP protocols (TCP, UDP, ICMP, etc.) work. |
| `none` | SLIRP `restrict=on` blocks all outbound traffic. SSH and HTTP port forwards from the host still work. |
| `rules` (default) | Ordered CIDR allow/deny rules enforced via an LD_PRELOAD filter on passt. First match wins; default policy is deny. All IP protocols are subject to the rules. |

The mode is chosen at init (`--network MODE`) and stored in `config.json` as `.network`: the string `"full"` or `"none"`, or an object `{"rules": [...]}` for rules mode.

Note for `none` mode: every supported harness needs access to a model provider's API. In `none` mode they won't function unless API access is provided through another channel (e.g. SSH port forwarding).

## L4 CIDR rules

### The seeded ruleset

A new rules-mode instance is seeded with deny rules for private (RFC1918), link-local (including cloud metadata `169.254.169.254`), and bogon ranges, followed by `allow 0.0.0.0/0` for the public internet. Net effect: working internet out of the box, with LAN and metadata services blocked. Rule objects may optionally carry a `comment` field; it's preserved through edits and shown by `rules list` but ignored by the filter.

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

### Host-topology keys (`implicitDns`, `selfAddrs`)

Two optional `.network` keys describe the machine cogbox itself runs on, rather than a user policy. Both are absent by default and are seeded at `cogbox init` time by whoever provisions the instance -- never by the `rules` verbs:

| Key | init flag | Effect |
|---|---|---|
| `"implicitDns": false` | `--no-implicit-dns` | Removes the implicit port-53 allow (see [Enforcement internals](#enforcement-internals)), so DNS walks the ordered rules like any other port. |
| `"selfAddrs": ["10.0.0.5/32"]` | `--self-addr` (repeatable) | Adds each address to the L7 proxy's [non-overridable hard floor](#how-l7-composes-with-l4). |
| `"dnsHost": "127.0.0.53"` | `--dns-host` | Re-admits **exactly one address on port 53** to the rule walk: the loopback DNS forwarder the enclosing host runs. One bare address -- a prefix, a port or a proto qualifier is refused, because any of them would turn a one-socket exception into a loopback carve-out. |

All three are rules-mode only: `full` and `none` store `.network` as a bare string, have no L4 filter to parameterize and no proxy to give a floor to, so `cogbox init` warns and ignores them there. They render into the runtime rules file as the directives `no-implicit-dns`, `hard-deny <cidr>` and `dns-host <addr>`, ahead of every rule, and hot-reload with everything else.

Set them where the host's own resolver or addresses are things the sandbox must not reach -- a cloud VM whose DHCP resolver is also its metadata server is the motivating case. `--no-implicit-dns` and `--dns-host` are two halves of one arrangement: the first puts loopback DNS back under the filter's loopback deny, and the second re-opens the single socket passt re-emits the guest's forwarded queries on (`COGBOX_GUEST_RESOLVER` + `COGBOX_HOST_RESOLVER`, see [Host-integration knobs](#host-integration-knobs)). Use `--no-implicit-dns` **without** either and the guest's DNS has to reach a resolver the rules allow on its own -- one inside a denied range leaves it with **silently** broken DNS, because its queries are dropped like any other denied packet.

### How rules are evaluated and edited

Rules are evaluated top-to-bottom on every outbound packet; the first matching rule wins, and a packet that matches no rule is denied. **Position matters**: a rule only fires if no earlier rule matches the same address first.

The `rules add` command **appends by default** -- the new rule lands at the bottom of the list, after the seeded `allow 0.0.0.0/0` catch-all. That position is almost always wrong: the catch-all matches everything public, so an appended `deny` or `allow` for a public address is unreachable. Pass `--at N` to insert at 1-based position `N`, shifting existing rules down. To see current positions, run `rules list`.

Two practical patterns:

**Allow a specific LAN host** -- insert the allow ahead of the matching deny. Use `rules list` to find the right index for the deny:

```sh
cogbox rules list
# ...
# 8: deny 192.168.0.0/16  # RFC1918 private
# ...
cogbox rules add allow 192.168.1.50/32 --at 8
```

**Block a specific public address** -- insert the deny ahead of the trailing `allow 0.0.0.0/0`. Easiest is `--at 1` so it runs before all existing rules:

```sh
cogbox rules add deny 8.8.8.8/32 --at 1
```

**Allow only one port on a host** -- scope the allow with a proto and `:PORT`, then deny the rest of the host. The narrower rule must come first:

```sh
cogbox rules add allow tcp 1.2.3.4/32:443 --at 1   # HTTPS to that host
cogbox rules add deny 1.2.3.4/32 --at 2            # nothing else to it
```

Implicit rules (applied before user rules, not configurable):

- **DNS (port 53)** is always allowed so hostname resolution works
- **Loopback (127.0.0.0/8, ::1)** is always denied to prevent the VM from accessing host services via passt's gateway-to-loopback mapping

### Rule format

CIDR rules accept optional `tcp`/`udp` and `:PORT` qualifiers, both via `cogbox rules add` (e.g. `cogbox rules add allow tcp 1.2.3.4/32:443`) and when hand-edited in `config.json`. The runtime file format is:

```
allow 10.0.0.0/8                 # any proto, any port
allow tcp 10.0.0.0/8             # tcp, any port
deny  0.0.0.0/0:25               # any proto, port 25
allow tcp 0.0.0.0/0:443          # tcp, port 443
```

IPv6 CIDRs are matched port-less only (e.g. `deny tcp ::/0`); the `:PORT` qualifier is IPv4-only in v1, so a rule like `allow tcp ::1/128:443` is rejected.

### Rules verb reference

| Form | Description |
|---|---|
| `cogbox rules list [-n NAME]` | List current rules with 1-based indices |
| `cogbox rules add allow\|deny [tcp\|udp] CIDR[:PORT] [--at N] [-n NAME]` | Add a rule. An optional `tcp`/`udp` proto and `:PORT` narrow the match (both default to any). Appends by default; `--at N` inserts at 1-based position N. |
| `cogbox rules del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox rules set [-n NAME]` | Replace all rules from stdin |

If the instance is running, rule changes take effect immediately: the runtime rules file is regenerated and passt receives `SIGUSR1` to reload.

### Enforcement internals

The filter works by intercepting passt's outbound `connect()`, `sendto()`, `sendmsg()`, and `sendmmsg()` syscalls. Since passt is the VM's only network path, this is a complete enforcement point. The filter is a Zig shared library (`libnetfilter.so`) loaded via `LD_PRELOAD`; it initializes via `.init_array` (before `main()`) so that all file I/O for rule loading completes before passt activates its seccomp-bpf sandbox. Denied connections receive `ENETUNREACH`.

The `cogbox rules` subcommands edit `config.json`, regenerate the runtime rules file, and signal the running passt, so rule changes take effect without restarting the VM. The CLI shares the on-disk rule format parser with the LD_PRELOAD filter, so the formats stay in sync.

Two implicit rules sit above the user rules, in this order:

1. **Port 53 is allowed**, to any destination, before the walk. It exists so a loopback resolver (`127.0.0.53`/systemd-resolved) keeps working, and it is checked first, so DNS also escapes the L7 mode's IPv6 fail-close, the seeded link-local deny and every private-range deny. `--no-implicit-dns` (`.network.implicitDns = false`) turns it off for an instance; the loopback deny below then applies to DNS as well.
2. **Loopback is denied.** passt translates traffic aimed at the guest's default *gateway* into `127.0.0.1` on the host (`--map-host-loopback`, whose default is the gateway address; `--no-map-gw` turns it off), so allowing loopback would expose every host service to the sandbox. The remap path bypasses this deliberately (it never evaluates the rewritten destination). Note that this is the gateway address, **not** the host's own address: the guest is assigned the host interface's address by passt's DHCP, so it cannot name the host that way at all.

One known boundary: traffic handled internally by passt (ARP, DHCP, gateway ping responses) never reaches the intercepted syscalls and is not subject to user rules.

### Host-integration knobs

Environment variables read by the launcher, all empty/off by default -- set by whatever provisions the host, never by a user. With none of them set, cogbox runs the exact command line it ran before they existed.

| Variable | Effect |
|---|---|
| `COGBOX_PASST_RUNAS` | Run passt under a dedicated uid (`--runas`) instead of the ambient `nobody` it self-drops to, so a host packet filter can express "guest-originated" as a uid match. Needs the launcher to start as root (or hold `CAP_SETUID`). Applied in `rules` **and** `full` mode -- `full` is the one with no L4 filter at all, so the host's rule is its only floor. |
| `COGBOX_PROXY_RUNAS` | Run the L7 proxy and the mitmproxy terminate backend under `user[:group]` (`setpriv`). The proxy re-resolves an allowed vhost and opens the upstream socket under **its own** uid, so a passt-only uid rule leaves it as an unscoped relay. Its runtime dir, per-instance CA dir and mitmproxy confdir must be writable by that uid, and whatever sends the hot-reload signals (`SIGHUP`/`SIGUSR1`) must be allowed to signal it. |
| `COGBOX_GUEST_RESOLVER` | Advertise this address to the guest as its resolver **and intercept its queries to it** (`passt --dns-forward`), plus stop mapping the gateway to the host (`--no-map-gw`). The address is a handle, not a destination: passt consumes the guest's DNS at the tap and re-emits it host-side, so nothing ever routes to it. The two flags go together: `--no-map-gw` is what closes passt's DNS carve-out (traffic to the mapped gateway on port 53 is forwarded to the *host's* resolver rather than translated to loopback, so it never looks like loopback to the filter), but it also disables the remap of loopback resolvers from `/etc/resolv.conf` -- which is how a dev box running systemd-resolved gives its guests DNS at all. Dropping that mapping is therefore only safe when an explicit guest resolver replaces it. **Not `-D`:** passt applies `-D` before reading `/etc/resolv.conf` and then skips the read, leaving `dns_host` unspecified and its own forwarding silently disarmed. |
| `COGBOX_HOST_RESOLVER` | Where those intercepted queries go (`passt --dns-host`): the loopback DNS forwarder on the enclosing host. Only applied together with `COGBOX_GUEST_RESOLVER`. A bare address -- passt parses it with `inet_pton`, so `host:port` is rejected -- and unlike `--dns-forward` it accepts a loopback one. The guest then resolves exactly what the host resolves, which is the point on a host whose real resolver the sandbox must not reach. Pair it with `cogbox init --dns-host <same address>` so the L4 filter admits that socket in `rules` mode, and with a rule in the host's own packet filter if it has one. |
| `COGBOX_PASST_BIND_FORWARDS` | Bind the guest's SSH/HTTP forwards to `.bindAddr` instead of every address. Opt-in: the default `.bindAddr` is `127.0.0.1`, and deployments that reach the forwards at a pod or host address depend on the wildcard bind. |

Whichever way the guest is handed its resolver, that resolver is the **only** one
it has: the guest image pins systemd-resolved's `FallbackDNS` to empty, so the
compiled-in public list (1.1.1.1, 8.8.8.8, 9.9.9.9, ...) never stands behind the
link-scope server. Without that pin, a guest whose link-scope DNS is unset or
failing falls through to a third-party resolver -- which does not merely answer
with public data, it *sends the internal query name off-site* and turns an
internal-DNS outage into an ordinary-looking NXDOMAIN. Empty means such a lookup
fails visibly instead. The `guest-dns-no-public-fallback` flake check asserts it
against the rendered `resolved.conf`.

Both `RUNAS` uids exist so a host filter can name them, and the GCE image's
`cogworx-floor.service` (`gce/floor.nix`) is the deployment that does: link-local
is dropped for the passt uid, and OPENING a flow to the VM's own non-loopback
addresses is dropped for **every** uid --
`meta skuid 0-4294967294 ct direction original ip daddr <self> drop` -- with the
control uid admitted to the guest SSH forward range above it so `cogbox ssh`
still works. Every part of that spelling is deliberate.

It cannot be narrowed to `skuid cogbox-passt` / `skuid cogbox-proxy`, because
in-VM nix builds run as `nixbld*` under the daemon and passt creates its
port-forward listeners *before* its privilege drop (`meta skuid` matches the
fsuid frozen in at socket creation, so those are root-owned).

It cannot be a blanket `daddr` drop with no `skuid` match either: on a same-host
connection the return packets carry the machine's own address as their
destination too, and the kernel's RST -- the reply when nothing is listening --
has no owning socket, so a `meta skuid` rule cannot match it and it survives. A
matchless drop swallows it.

And `skuid` alone does not save a reply that *does* have a socket. Once passt is
listening, the reply is a SYN-ACK from a real (pre-drop, root-owned) socket whose
destination port is the client's ephemeral port, so it matches no `dport` accept
and lands in the deny: an unscoped range would break `cogbox ssh`, Terminal,
Console-over-ssh and the user SSH gateway while still passing shape checks and
empty-port probes. `ct direction original`
scopes the deny to the direction that OPENS a flow, which is the rule's actual
intent. It is not `ct state new`: state-scoping would additionally exempt a flow
that survived a floor reload for that flow's whole lifetime, whereas direction is
a property of the packet and keeps the strength of the unscoped drop. It does
mean the VM's network namespace now runs conntrack, whose table is a finite
resource a busy guest can push on.

A guest gains nothing from the direction scoping: its first packet is the one
that opens the flow, the deny takes it, and a dropped OUTPUT packet is never
confirmed into conntrack, so no reply direction ever exists for it to ride.
Loopback is outside *that* rule so the L7 remap funnel is untouched; the proxy's
own `--self-addr` hard floor covers the relay path a second time.
`tests/test_floor.sh` loads the rendered ruleset into a throwaway netns and probes
it with a real listener bound, because that is the only setup in which the broken
and the correct rule behave differently.

Loopback gets its own rule, and deliberately the **opposite** shape:
`meta skuid cogbox-passt ct direction original ip daddr 127.0.0.0/8 drop` (plus
the `::1` mirror), with the funnel's own targets accepted above it as an explicit
port set -- `127.0.0.1:<l7base>` and `+1` for each triple `cogbox start` may slide
onto. It stays scoped to the passt uid rather than covering every uid because
loopback is where the trusted half talks to *itself*: l7proxy dials the mitm hop,
mitmproxy dials its upstreams, sshd and the nix daemon live there. passt is the
only process that turns guest bytes into host sockets, and its per-flow outbound
sockets are created after the privilege drop, so that one uid is both necessary
and sufficient. The third port of each triple -- the mitmproxy SOCKS5 hop, dialed
by l7proxy under the *proxy* uid -- is deliberately not in the set, which is why
it is a set and not a port range. `ct direction original` matters here for the
same reason it does on rule 2: the funnel's SYN-ACK carries `daddr 127.0.0.1` and
the client's ephemeral port, so a stateless deny would eat every funnel reply and
take L7 down.

The rule is defence in depth, and what it is defending is worth naming so nobody
removes it as redundant. A guest cannot address the enclosing machine over
loopback today for two reasons that are both upstream C: passt drops tap frames
carrying a loopback source or destination, and `--no-map-gw` removes the
gateway-to-loopback mapping that would otherwise turn an address the guest *can*
name into `127.0.0.1` on the host. In `full` mode there is no L4 shim, so this
rule independently enforces the loopback half of "a guest cannot reach the
host's services." The funnel's remap table is also rendered from
`.network.remap`, which accepts an arbitrary single loopback target, so anything
that can write an instance's config can aim passt's own `connect()` at
`127.0.0.1:22`.

> **Testing note.** An in-guest probe of the *host's own address* proves nothing.
> passt assigns the guest the host interface's own address over DHCP ("its own
> address shadows that of the host", `passt(1) --map-guest-addr`), so a connect to
> that address from inside the guest is delivered inside the guest -- to the
> guest's own sshd, whose banner matches the host's when both run the same
> nixpkgs. The floor's counters correctly stay still, because nothing was sent.
> Compare SSH **host keys**, or probe a port only the host binds.

Where the launcher's stderr is collected somewhere retained outside the machine (a cloud serial console, say), what it prints on a failure matters. Its error paths name **files, instances and harness keys, never credential values** -- the redaction failures say "token withheld" rather than echoing the token -- and it never dumps its environment or its own argv. One deliberate exception: an argument the Zig wrapper did not recognize is echoed back verbatim in `cogbox-launch: error: unexpected argument <arg>`, since the whole point of that branch is to name the offending token. It is unreachable through the CLI (the wrapper validates first) and only matters to something invoking the script directly with a secret in an argument position -- which is already the wrong shape: credentials reach cogbox on stdin or through a file, never argv.

## TCP destination remap

A second, independent table redirects outbound TCP connects from specific `(cidr, port)` destinations to a loopback target on the host. When a match fires, the shim drives a SOCKS5 v5 CONNECT handshake on the connecting fd, carrying the original `(ip, port)` to the target proxy -- so the downstream proxy sees the guest's real intended destination. v1 supports TCP only; the target must be a single host.

| Form | Description |
|---|---|
| `cogbox remap list [-n NAME]` | List current remap rules with 1-based indices |
| `cogbox remap add FROM TO [--at N] [-n NAME]` | Add a rule. `FROM` and `TO` are single quoted args, e.g. `"tcp 0.0.0.0/0:443"` and `"tcp 127.0.0.1:18080"`. |
| `cogbox remap del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox remap set [-n NAME]` | Replace all rules from stdin (one `FROM -> TO` per line) |

Example: send every outbound TCP/443 connection through a SOCKS5 proxy running on `127.0.0.1:18080`:

```sh
cogbox remap add "tcp 0.0.0.0/0:443" "tcp 127.0.0.1:18080"
```

The CIDR + remap tables share one runtime rules file; edits to either verb rewrite both sections cleanly without dropping the other layer. Like L4 rules, remap edits hot-reload into a running instance.

The remap table is also the substrate for [L7 host filtering](#l7-host-filtering): enabling L7 auto-injects remaps that funnel guest web traffic into the host-side proxy.

## L7 host filtering

L4 rules whitelist a destination *IP*. That is not enough when several virtual hosts share one load-balancer IP: allowing the LB lets the sandbox reach **every** backend on it by guessing the `Host`/SNI. The `l7` layer whitelists individual vhosts instead.

### The model

When `.network.l7` has any rule, cogbox starts a small host-side proxy and funnels **all** guest 80/443 traffic to it (via an auto-injected `remap`). For each connection the proxy reads the vhost from the TLS **SNI** (HTTPS) or **Host** header (HTTP), checks it against your `allow`/`deny` list (first match, default deny; patterns are exact / `*.suffix` / `*`), and on allow **re-resolves that name itself, host-side**, then splices the bytes through. Re-resolution is the point: the guest's chosen IP is discarded, so

- allowing one vhost does **not** expose siblings on the same IP, and
- DNS-based load balancing (rotating/shared IPs) keeps working, because the proxy always resolves the allowed name fresh.

```sh
cogbox l7 add allow api.example.com        # only this vhost on its LB
```

L7 rules live under `.network.l7` and require the instance's network mode to be `rules`. Edits hot-reload the proxy (`SIGHUP`) and passt (`SIGUSR1`).

### How L7 composes with L4

The proxy re-resolves the allowed name **host-side** (it never trusts the guest's IP or a guest-supplied Host/SNI as a destination), so an L7 rule refines the L4 IP policy by name. For each re-resolved IP, on funneled web traffic:

| vhost vs. L7 rules | decision |
|---|---|
| explicitly **allowed** | **dial** -- supersedes an L4 IP *block* |
| explicitly **denied** | **drop** -- supersedes an L4 IP *allow* |
| **not in any rule** | defer to L4 (dial if the IP is allowed, drop if blocked) |

...and a **non-overridable hard floor** (loopback, this-network `0.0.0.0/8`, and link-local incl. cloud metadata `169.254.169.254`) is *always* dropped, even for an allowed vhost.

That built-in set is topology-independent, so it cannot include the address of the machine cogbox is running on -- and since an explicit L7 allow supersedes the L4 IP check, a sandbox owner who controls a DNS zone could otherwise point a name at that machine, allow the name, and obtain a guest-triggered connection back into the host half (under the *proxy's* uid, not passt's). Per-instance `--self-addr` entries (`.network.selfAddrs`, rendered as `hard-deny <cidr>`) extend the floor with exactly those addresses. They apply to every proxy dial path -- named splice, terminate handoff, and the raw-L4 splice -- and, being a floor, are never superseded by an allow. Loopback is untouched, so the L7 funnel itself keeps working.

**Path constraints fail closed.** When an `allow` rule names a host but adds a path prefix (`allow api.example.com /v1/`), a request to that host on an *uncovered* path (e.g. `/v2/`) is **dropped**, not deferred to L4 -- otherwise the constraint would be silently bypassed whenever the IP is independently L4-allowed (the usual "allow the internet at L4, restrict vhosts at L7" setup). A `deny` rule with a path (`deny api.example.com /admin/`) only blocks that prefix and leaves other paths to L4, since you're carving out a hole, not whitelisting. On HTTPS this is enforced by the terminate tier; on cleartext HTTP the proxy enforces it inline from the request line.

So to reach an internal vhost on a private LB, you just allow the **name** -- no L4 IP rule, and you never open that IP for anything else:

```sh
# 10.10.10.10 hosts a.internal and b.internal; reach ONLY a.internal:
cogbox l7 add allow a.internal          # leave 10.10.10.10 blocked (default deny 10/8)
# a.internal -> allowed -> dialed;  b.internal -> unlisted -> IP blocked -> dropped
```

Conversely, sibling isolation only applies where the LB's **IP is blocked**. On a public LB reachable via `allow 0.0.0.0/0`, an unlisted sibling falls back to L4 and is allowed; block the IP (or `l7 add deny sibling`) to restrict it.

> **Wildcard caveat.** A `*.suffix` allow trusts that whole domain's DNS -- if an attacker can create `evil.suffix` pointing at an internal IP, it would be dialed (metadata/loopback/link-local still blocked by the hard floor). Exact-name allows have no such exposure (you control that name's DNS); only wildcard a suffix whose DNS you trust.

### Tiers: terminate and passthrough

There are two tiers, chosen per host. **Terminate is the default**:

- **Terminate (default)** -- the proxy MITMs the host's TLS via a per-instance CA so it can enforce `Host == SNI` and URL paths -- see [the terminate tier](#the-terminate-tier). This breaks cert-pinned clients, so opt those out with `--passthrough`.
- **Passthrough** (`--passthrough` per host, or `l7 mode passthrough` for the whole instance) -- TLS is *not* intercepted, so cert pinning is preserved, but the proxy trusts the SNI it sees: a shared ingress that routes by the inner `Host:`/HTTP-2 `:authority` could still be steered to a sibling on a single connection, and URL paths can't be inspected on HTTPS. Because that cleartext SNI is the *only* routing signal, an [ECH-bearing](#l7-caveats) ClientHello is refused on this tier.

**Harness API endpoints auto-passthrough.** Because terminate is the default, the in-guest agents' own control-plane endpoints (`api.anthropic.com`, `api.openai.com`, `chatgpt.com`, etc.) are automatically kept in passthrough, so the harnesses keep working out of the box (notably rustls clients that may not honor the injected CA) and their API tokens stay end-to-end. An explicit `--terminate` on such a host overrides it; provider-agnostic harnesses (opencode, omp, pi, hermes-agent) should `--passthrough` their configured provider hosts when termination is inappropriate.

### The terminate tier

By default every allowed host is routed through a TLS-terminating proxy ([mitmproxy](https://mitmproxy.org/)) so cogbox can see inside HTTPS (use `--passthrough` to opt a host out, or a `--path` prefix to add path enforcement). This closes the passthrough gaps:

- enforces `Host == SNI` (a connection whose decrypted `Host:`/`:authority` disagrees with the negotiated SNI is rejected with `403`), and
- enforces **URL path prefixes** (`--path /v1/`), boundary-aware and applied to the normalized, percent-decoded path, and
- **strips HTTP method-override headers** (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`) from every request it sees. Rules are matched on the *wire* method, while frameworks such as Rack rewrite the request to the method one of those headers names -- so leaving one in place would let a method the rules allow (`POST`) be executed by the origin as one they exclude (`DELETE`), with the host-side credential already injected. Stripping is unconditional, so the origin always acts on the same method the decision was made on. Residual, stated rather than assumed away: Rack also honours a `_method` field in a form-encoded **body**, and this proxy is header-only by construction (pack-endpoint bodies are streamed, never buffered).

**A request whose path carries a `.` or `..` segment is refused with `403`** -- at both tiers, before any rule is consulted and before any credential is injected. Dot segments are *rejected, never collapsed*, because the enforcer decides on the normalized path but forwards the **original raw path** upstream: percent-decoding can only ever *add* segments (a `%2F` becomes a real separator), which narrows a left-anchored rule, whereas popping `..` *removes* them -- so `/a/denied/..%2Fallowed` would be authorized as `/a/allowed` while the origin stays free to route the raw form. Only a whole `.`/`..` segment is refused; dots inside a segment (`/a/..b`, `/v1.2/x`) are ordinary data, and `//` still collapses. No normal HTTP client emits a dot segment.

```sh
cogbox l7 add allow git.example.com --path /myorg/   # only this path prefix
cogbox l7 mode terminate                             # terminate every L7 host
```

**Single-segment path wildcards.** A `--path` segment that is exactly `*` matches **exactly one** request segment and never spans a `/`: `--path /api/v4/projects/*/issues` matches `/api/v4/projects/1234/issues` and everything under it, but not `/api/v4/projects/1234/access_tokens` and not `/api/v4/projects/a/b/issues`. A segment that is exactly `#` is the same thing **narrowed to ASCII digits** (`[0-9]+`), for a segment that is a numeric identifier by construction: `--path /api/v4/projects/#/issues` matches `/api/v4/projects/1234/issues` but not `/api/v4/projects/mygroup/issues`. Either character outside a whole segment (`/a*`, `/b#c`) is a literal, and either one in the *request* is always literal -- the request side is data and is never interpreted. `--exact` compares the path literally and does **not** honour either wildcard.

Three properties matter when writing rules with them:

- **The rule is still a prefix.** `--path /a/*` also matches `/a/b/c`. Only a path ending in a *literal* segment is bounded.
- **Matching happens on the percent-DECODED path,** so an encoded slash (`%2F`) is a real separator and inflates one addressed segment into several. A wildcard **deny** in front of a broader allow therefore fails *open* -- a left-anchored matcher cannot suffix-anchor a deny. Put the boundary in the allow, never in a deny.
- **Terminating an allow at a literal segment is necessary but not sufficient -- prefer `#` for an id.** If the caller chooses the wildcard segment's value (an "ID or URL-encoded path" style parameter), it can pick one whose *own last component is the rule's literal tail*: with `--path /a/*/tail`, the request `/a/x%2Ftail/anything` decodes to `/a/x/tail/anything`, `*` absorbs `x`, the tail is satisfied by the id's second component, and `/anything` rides through as ordinary prefix continuation. `#` closes that whenever the segment is numeric, because the absorbed component would then have to be all digits. The `tail absorption` block in the vector table pins both directions.

> **Upgrade note -- this changes the meaning of existing rules.** Before this release `*` and `#` in a `--path` were literal bytes, so a rule written as `--path /v1/*/chat` in the hope of globbing matched essentially nothing (fail closed). It now matches one segment. On upgrade, **audit every persisted rule set for a `*` or `#` path segment** -- each instance's `config.json` (`.l7.rules[].path`) and any rule set a control plane pushes -- because for an `allow` this is a silent widening applied by a rolling image roll. There is no escape for a *literal* `*`/`#` as a whole segment; if you need one, express the rule with `--exact`, which compares literally and does not honour the wildcards.

The Zig proxy (cleartext + passthrough) and the mitmproxy addon (terminate) implement this identically, asserted from one shared vector table -- `zig/src/l7proxy/path_vectors.tsv`, read by both `zig build test` and `tests/test_l7_addon.py`. Change one matcher and its own suite fails; realign the table for one matcher and the other suite fails.

How it works: every rules-mode instance runs mitmproxy with a **per-instance CA** (auto-generated under `~/.config/cogbox/instances/<name>/l7-ca/`, key stays host-side at mode `0600`) -- started at every boot, even with no L7 rules yet, so that hot-added rules terminate immediately and the CA is in the guest trust store from the start (it can only be injected at launch). The CA **certificate** (never the key) is injected into the guest at boot via `fw_cfg` and assembled into `/run/cogbox/ca-bundle.crt`; the harness launchers and login shells point `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` at it. Those env vars only reach OpenSSL/Node/git-style clients, so `cogbox-l7-trust.service` *also* imports the CA into root's **NSS database** (`/root/.pki/nssdb`) -- the trust store Chromium reads on Linux -- so browser-driven plugins (e.g. headless Chromium under Playwright, which ignores the env vars and the bundle file entirely) trust the terminate tier too. The Zig proxy still does all SSRF/CIDR vetting and hands mitmproxy only a pre-vetted IP; mitmproxy mints a per-SNI leaf, applies the rules, and re-originates upstream TLS validated against the *real* system trust.

**Upstream cert verification (`--insecure-upstream`).** Because the proxy re-originates TLS, it -- not the guest -- validates the upstream certificate (against the real system trust, by SNI). The guest's `curl -k` can't relax this: `-k` only covers the guest<->proxy leg, which is the always-valid minted leaf. So a terminate host whose upstream has a self-signed or name-mismatched cert fails with mitmproxy's `502 Bad Gateway -- Certificate verify failed` (common for internal services). Mark such a host `--insecure-upstream` to skip verification on **its** proxy<->upstream leg only -- the operator's per-host equivalent of `curl -k`:

```sh
cogbox l7 add allow internal.svc --insecure-upstream    # MITM, don't verify its upstream cert
cogbox l7 add allow internal.svc --path /v1/ --insecure-upstream
```

Verification stays **on** for every other host (fail closed); the flag is a deliberate per-target exception. If you only need to *whitelist* a bad-cert host (no path/`Host` enforcement), prefer passthrough instead -- there the guest keeps end-to-end TLS and its own `curl -k`.

Terminate caveats:

- This is an **intentional MITM**: for terminate hosts the proxy sees plaintext (host-process-only, never persisted). Cert pinning is **broken** for those hosts -- clients that pin a specific cert/CA (some Go and mobile apps) will fail; leave them on passthrough.
- The CA reaches OpenSSL/Node/git clients (via the env vars), curl/python, and NSS clients including Chromium (via root's NSS db, imported by `cogbox-l7-trust.service`). What's still **not** covered: a client that ships its **own** embedded trust store and consults neither the env vars nor any system/NSS store -- e.g. Rust `rustls` pinned to the bundled `webpki-roots` crate. The `codex` harness is Rust and uses `rustls`, but it links `rustls-native-certs`/`native-tls` and references `SSL_CERT_FILE` with **no** bundled `webpki-roots` (per binary inspection of 0.139.0), so it loads system roots and should honor the injected CA -- worth a quick runtime check. Passthrough is unaffected regardless. (The NSS import targets root's db, so a plugin running a browser as a non-root user with a different `$HOME` would need its own import.)
- HTTP/2 to the client is disabled (http/1.1 only) so every request's authority is checked against the SNI.

### Per-instance ports

The proxy and its mitmproxy terminate backend bind **per-instance** loopback ports (a contiguous triple from each instance's `l7PortBase` in config.json, default 18443: TLS funnel / HTTP funnel / terminate hop), so several L7-enabled instances run on one host without one instance's guest traffic funnelling into another's proxy. Named instances auto-assign disjoint triples at init -- but only disjoint among *one user's* instances. Because the triple binds the host's shared loopback, a different user's instance (or any process) can hold it on a multi-user host, so at launch `cogbox start` probes the triple and, if it is taken, slides to the next free triple and persists it back to config.json (`cogbox-launch: L7 port base ... in use; using ... instead.` in the log). Only if the proxy still can't bind -- e.g. a port grabbed in the race between probe and bind -- does `cogbox start` **abort** rather than boot a VM whose funnel can't reach its proxy.

### L7 verb reference

| Form | Description |
|---|---|
| `cogbox l7 list [-n NAME]` | List current L7 rules and the instance mode |
| `cogbox l7 add allow\|deny HOST [--passthrough \| --path P \| --terminate [--insecure-upstream]] [--at N] [-n NAME]` | Add a rule. `HOST` is an exact name, a `*.suffix` wildcard, or a bare `*`. Hosts **terminate by default**; `--passthrough` opts a host out (SNI-only, for cert-pinned clients). `--path`/`--terminate` force terminate; `--insecure-upstream` skips upstream cert verification (implies terminate). A `--path` segment that is exactly `*` (any one segment) or `#` (one all-digit segment) is a single-segment wildcard (see [the terminate tier](#the-terminate-tier)); `--exact` honours neither. This verb's grammar is a deliberate back-compat pin — it is what an old control plane falls back to — so it applies no whitespace or control-character restriction to its values: a padded `HOST` parses and is stored padded (the DNS-pattern validator trims before validating), and a whitespace-bearing `--path`/`--service` is accepted and then silently drops the whole rule at the enforcer, which is whitespace-tokenized. That restriction is a property of the line format, so it lives in `replace`. |
| `cogbox l7 del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox l7 clear --plugin TAG [-n NAME]` | Drop every rule tagged `TAG` (the `"plugin"` field an `add --plugin` stamps) |
| `cogbox l7 replace --plugin TAG --from-stdin [-n NAME]` | Drop every rule tagged `TAG` and append the rule set read from stdin in its place, stamped with the same `TAG` — ONE config edit and ONE reload. Each line is the argv tail of `add` (`allow\|deny HOST [flags...]`), tokenized on space/tab, with blank and `#` lines skipped. `--at`, `--plugin` and a `tag=` token are rejected per line: the tag is argv-level exactly once, which is what stops one tagged batch from writing rules owned by another tag. A token carrying whitespace or a control character is rejected too — the format is whitespace-tokenized and newline-delimited, and a newline would split one rule into two with the second half inheriting the invocation's `TAG`. Rules append in stdin order, after every other rule. If the **resulting rendered rule-line count** would exceed the enforcer's rule cap **and the batch is larger than the tagged set it replaces**, the whole replace is refused with exit 65 and the config is left untouched — never truncated, because the proxy compiles only the first cap lines while the terminate-tier addon reading the same file has no cap, so a dropped tail makes the two layers disagree. Rendered *lines*, not `.l7.rules[]` entries: the renderer also emits one `allow HOST terminate` per inject-spec host that no rule names, so a result whose array fits can still render a document that does not. Only a replace that *grows* the rule set is refused: `l7 add` is **uncapped**, so the clear-then-add sequence this verb replaces can leave an already-over-cap array behind, and on such an instance a revoke (an empty batch) or a narrowing edit must still succeed or the withdrawn rules would stay in force with no way to remove them. |
| `cogbox l7 set [-n NAME]` | Replace all rules from stdin (one `allow\|deny HOST` per line) |
| `cogbox l7 mode passthrough\|terminate [-n NAME]` | Set the instance default tier (terminate if unset) |

```sh
cogbox l7 add allow api.example.com                       # terminate (default)
cogbox l7 add allow pinned.example.com --passthrough      # SNI-only (cert pinned)
cogbox l7 add allow api.example.com --path /v1/           # terminate + path
cogbox l7 add deny '*' --at 1                             # explicit default-deny for vhosts
```

A rendered rule line may also carry a trailing `tag=<name>` token (e.g. `tag=git-grants`, stamped on compiled git-grant rules). Both wire parsers handle it: the Zig proxy **accepts and ignores** it (it plays no part in allow/deny or tiering), and the mitmproxy addon **uses** it for credential-injection gating (an inject spec's `rules_tag` must match a rule's `tag` for the token to be injected -- see [Host-side credential injection](#host-side-credential-injection)). A line carrying any genuinely-unknown token is still dropped fail-closed by both.

### L7 caveats

Documented, not silently assumed safe:

- **QUIC / UDP-443 and all guest IPv6** are denied while L7 is active (the funnel is IPv4/TCP-only), so clients fall back to inspectable IPv4 TCP. DNS (port 53) still works -- unless the instance was initialized with `--no-implicit-dns`, in which case DNS obeys the rules like everything else and the IPv6 fail-close covers it too.
- Loopback, this-network, and link-local/metadata vhosts are never reachable through the proxy (the hard floor) -- consistent with the sandbox's LAN posture for those specific ranges. Add the host's own addresses with `--self-addr` if the deployment needs them covered too; the built-in floor cannot know them.
- **Encrypted ClientHello (ECH)** is refused on **passthrough** hosts (logged `ech-on-splice`): the cleartext SNI that passthrough routes on could be a decoy for an encrypted inner name, so it can't be trusted to identify the real host. **Terminate** hosts accept ECH -- mitmproxy is the TLS endpoint and re-checks `Host == SNI` on the *decrypted* request, so an inner name can't be smuggled past it. Chrome/Chromium send a GREASE ECH extension on every handshake by default, so a browser client reaching a vhost must be on the terminate tier (the default); only an explicitly `--passthrough` vhost would drop it.

## Host-side credential injection

By default, cogbox inherits the harness's auth from the host by mounting the host's credential files into the guest (see [harnesses](harnesses.md)). Those files carry the agent's long-lived secrets -- for the OAuth harnesses, an `accessToken` and a `refreshToken` (in `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.local/share/opencode/auth.json`, `~/.pi/agent/auth.json`, or OMP's `~/.omp/agent/agent.db` SQLite store); for hermes-agent, the provider API keys in `~/.hermes/.env`. A compromised or prompt-injected agent inside the sandbox can read them.

Host-side credential injection removes the secret from the sandbox. Because the terminate tier already MITMs a host's TLS host-side, the proxy can **rewrite the request's auth header** with the real token read from the host's own credential file -- so the guest only ever carries a stub, and the real token (especially the refresh token) never crosses the 9p / fw_cfg boundary into the VM.

### How it works

When an **inject-conf** is present (path in `COGBOX_L7_INJECT_CONF`, passed to the mitmproxy backend by `cogbox-launch.sh`), the terminate-tier addon (`l7-mitm-addon.py`), on every decrypted request whose host matches a configured spec, **after** the allow + `Host == SNI` checks pass, replaces the auth header from a host-side credential file:

- the conf is a JSON list of specs `{host, style, cred_file, token_path?, cred_format?, cookie_name?, account_id_path?, refresh?, stub_token?, rules_tag?}`;
- the addon reads `token_path` (a dotted path, e.g. `claudeAiOauth.accessToken`) out of `cred_file` and hot-reloads it on mtime change, so a rotated access token is picked up on the next request with no restart;
- injection is **scoped to the stub identity**: when the spec carries a `stub_token` (the placeholder redacted into the guest's cred file), the addon replaces the credential **only** when the request presents that exact stub -- or no credential at all. The guest's stub is thus overwritten with the real token, but a **secondary credential the guest legitimately obtained through an already-injected call** -- e.g. claude-code Remote Control's per-session `worker_jwt` -- is forwarded **untouched** instead of being clobbered (which would 401). A spec with no `stub_token` (harnesses that still mount their real token in-guest) always replaces, as before;
- if injection should fire for this request but the host-side token can't be read, the request **fails closed** (`403`) rather than forwarding the stub.
- when a spec carries `rules_tag`, the addon injects the credential **only if** the request is allowed by a rule bearing that tag (a second, tag-restricted evaluation over the same rule set). The full rule set still decides overall allow/deny, so a broad `allow <host>` grants **reachability** to the host but **not the token** -- the token rides only on a request a tagged rule matches. Emitted for the per-user `gitlab-oauth` bind as `rules_tag: git-grants`, matching the `tag=git-grants` wire token stamped on the compiled git-grant rules; a spec without `rules_tag` (the harness OAuth binds) is unaffected and injects on every allowed request as before.

`style` shapes the wire format: `bearer` (`Authorization: Bearer <token>`), `anthropic-oauth` (Bearer + `anthropic-beta: …,oauth-2025-04-20`, drops `x-api-key`), `anthropic-apikey` (`x-api-key`, drops `Authorization`), `openai-chatgpt` (Bearer + `ChatGPT-Account-Id`), and `cookie` (replaces **only** the named cookie -- the spec's `cookie_name` -- in the request `Cookie` header, leaving every other cookie verbatim). The conf and the credential files live **host-side only** -- they are never on a 9p share or fw_cfg slot, and `mitmdump` reads them as the launching user. For an **HTTPS** host this applies only on the **terminate** tier (so the addon sees the decrypted request); an explicit `cogbox l7 add allow <host> --passthrough` opts an HTTPS host out of both terminate and injection (the legacy "guest carries its own token end-to-end" behavior).

**Plain HTTP hosts.** Injection also works for cleartext `http://` vhosts -- the common case being an internal service with no TLS (e.g. an intranet app whose only credential is a session cookie). A plain-HTTP request carries no TLS to terminate and no SNI, so the proxy can't route it by the terminate tier; instead it routes a host's HTTP egress to the addon whenever that host appears in the inject-conf (the proxy reads the host list from a runtime `l7-inject-hosts` file derived from the same conf). The addon then skips the `Host == SNI` check (there is no SNI) but still enforces `allow`/`deny` + paths and stamps the credential exactly as for HTTPS. Two consequences worth understanding: (1) because the credential is stamped on the **cleartext** proxy<->upstream leg, only declare injection for a host you trust to receive that secret over the protocol it actually serves -- a host you reach over HTTPS but that *also* answers on `:80` could have its secret sent in the clear if the guest is steered to the HTTP port; (2) the **harness** provider hosts (`api.anthropic.com`, ...) are deliberately **excluded** from HTTP inject-routing -- they are HTTPS-only, so a guest cannot force a cleartext send of the real OAuth token by downgrading to `http://`. Only plugin/operator-declared inject hosts (and a hand-rolled `COGBOX_L7_INJECT_CONF`) are HTTP-routed.

### Default-on for new instances

A new rules-mode instance is **seeded for injection at init** for the harnesses the user is already **logged into** (a host-side cred file is present): `cogbox init` writes, under `.network.l7`, a `terminate` allow rule for each such harness's provider host(s) (`api.anthropic.com`, `chatgpt.com`, `api.openai.com`, ...) plus `"inject": true`. Nothing is seeded for a harness with no token yet (the `--yes` init activates all harnesses, but only logged-in ones are seeded) -- log in on the host first, or add the rule later. At launch, when `.network.l7.inject` is true, cogbox generates the inject-conf from the active harnesses' host cred files (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.local/share/opencode/auth.json`) into the runtime dir and points the terminate backend at it -- so injection works out of the box with no manual conf. The mapping is keyed on the **host**; if two harnesses provide the same host (e.g. claude-code and opencode both for `api.anthropic.com`), the first active one whose token file exists wins. Only specs whose host-side cred file exists are emitted; the rest fall back to the legacy path.

Opt a seeded host out by replacing its rule with passthrough -- `cogbox l7 add allow api.anthropic.com --passthrough` -- which drops both terminate and injection so the token goes end-to-end again (the legacy behavior); deleting the rule has the same effect. Setting `.network.l7.inject` to `false` stops the token rewriting but leaves the host on the terminate tier (still MITM'd, just not injected). Note that `cogbox l7 mode passthrough` does **not** opt a seeded host out: the seeded rule carries an explicit `terminate` that wins over the instance-default tier (`needsTerminate` precedence). An explicit `COGBOX_L7_INJECT_CONF=<path>` overrides the generated conf (used for testing or a hand-rolled mapping): it replaces both what the addon injects and the plain-HTTP inject-routing list (`l7-inject-hosts`). It does **not**, however, drive the netfilter funnel -- the per-port `remap` rules are rendered from `.network.l7.inject.specs[]` in `config.json` only (the funnel runs before any inject-conf is read). So an override-conf host on `:80`/`:443` is HTTP-routed and injected as usual, but one on a [non-standard port](#non-standard-ports) also needs a matching config spec carrying that `port`, or its egress never reaches the proxy to be injected.

### Keeping the token out of the guest

Injection rewrites the request host-side, but on its own the harness's credential file is still mounted into the guest (via the config/data overlay), so a compromised agent could read it directly. When injection is active, cogbox therefore **scrubs the secret from the guest**: the 9p source for that overlay becomes a per-instance hardlink-mirror of the host dir in which the credential file is **redacted** -- rewritten with its token fields replaced by inert placeholders, but its non-secret fields (the OAuth `scopes`, `subscriptionType`) kept -- so the real access/refresh tokens never enter the VM while the harness still sees a logged-in identity. (If the cred file has an unexpected shape and can't be redacted safely, staging writes a minimal placeholder-scoped credential instead -- a present, logged-in stub identity -- rather than risk writing a real token; only if even that write fails is the file dropped entirely.) The mirror is otherwise a hardlink copy (no bulk data copy -- the dir can be large), and the cred file's hardlink is broken before it is rewritten so the user's real file is never touched. The mirror lives host-only under the cogbox data root (`~/.local/share/cogbox/mirrors/<instance>/`), deliberately **not** under the instance's `instances/<name>/` data dir, which is shared read-write into the guest -- since the mirror is hardlinked to the real host dir, a guest write there would corrupt it. Hardlinking needs the mirror and source on the same filesystem (true when both live under `$HOME`); it falls back to a copy otherwise, and fail-closed to an empty dir, never the real dir. The rest of the config dir (settings, history, `CLAUDE.md`, ...) is preserved.

Because the redacted file keeps the OAuth `scopes`, claude-code starts up as a normally logged-in subscriber and the placeholder token is harmless: it sends the placeholder accessToken as a Bearer, the host proxy overwrites it on the wire (only over the stub) with the real token, and the far-future `expiresAt` stops the guest from ever trying (and failing) to refresh the placeholder itself. Keeping a real (logged-in) identity in the guest -- rather than the older "drop the file, run on an `ANTHROPIC_AUTH_TOKEN` env stub" approach -- is what lets features that gate on a **local full-scope credential** work under injection. `/remote-control` (`/rc`) is the motivating case: it checks the on-disk OAuth `scopes` before connecting (so the redacted-but-scoped file is essential), then mints an **ephemeral per-session `worker_jwt`** via an OAuth-authed call to `api.anthropic.com` (the stub is injected on that call), and runs its live transport (an SSE event stream + POSTs to `/v1/code/sessions/<id>/worker`) authenticated with that `worker_jwt`. Those transport requests also hit `api.anthropic.com`, but they carry the `worker_jwt` -- not the stub -- so the stub-scoped injection forwards them untouched; the earlier always-replace behavior clobbered the `worker_jwt` with the OAuth token, which the worker endpoint rejected (`401` -> `worker_register_failed` -> `Transport closed (code 403)`). A second terminate-tier subtlety surfaces in the same transport: its **inbound** leg (controller -> guest) is a long-lived **SSE event stream** (`GET .../worker/events/stream`), and mitmproxy **buffers response bodies by default** -- which stalls an open-ended stream, so the session connects and the **outbound** POSTs work but inbound events never flush (a one-way session). The addon's `responseheaders` hook sets `flow.response.stream = True` for `text/event-stream` responses so they pass through chunk-by-chunk (this also makes ordinary streaming inference truly stream rather than arrive all-at-once on close). The guest's `.credentials.json` is therefore **always present** -- a real redacted-scoped file on the happy path, or a minimal placeholder-scoped stub if staging fails -- so claude-code reads it, `/rc`'s on-disk scope gate is satisfied, and (crucially) an in-guest `/login` can write its OWN token over the placeholder. There is deliberately **no `ANTHROPIC_AUTH_TOKEN` env stub**: an injected auth-token env var would shadow the file, break `/rc`, and silently defeat in-guest login. Net: the **host's** access and refresh tokens never enter the sandbox; if a user logs in inside the VM with their own account, that token stays in that instance (see [In-VM login](#in-vm-login-per-instance-isolated) below).

**Keeping the injected token fresh (host-side refresh).** Scrubbing the token has a consequence: since the guest holds only a static placeholder and no refresh token, it can **never refresh on its own** -- so a long-running session would start getting `401`s the moment the host's short-lived access token lapsed. With nothing refreshing the host file -- the host's own CLI only keeps it warm while *it* is running -- the injected token eventually goes stale. To close this, an inject-conf spec may carry a `refresh` block (`{refresh_token_path, expires_at_path, token_url, client_id, expires_at_unit}`); cogbox emits one for the scrubbed **claude-code** host. When present, the addon does the OAuth refresh-token grant **host-side** as the access token nears expiry (default window 10 min; `COGBOX_L7_REFRESH_WINDOW_SEC`) and writes the rotated tokens back to the **same canonical credential file** the host's own CLI uses -- a single refresh-token lineage (a separate copy would fork the lineage and the provider's rotation would invalidate one side). It is serialized with `flock` in a host-only lock dir (never beside the cred file -- the mirror redacts the cred file but copies the rest of the dir, so a sibling token copy beside it would leak into the guest; no backup file is written for the same reason) and re-checks expiry under the lock, so it coexists with the host CLI refreshing the same file. The write is atomic (temp + `rename`, mode `0600`), and the whole path is **fail-safe**: any error -- unreadable file, network failure, malformed response, missing refresh token -- leaves the file untouched and the request proceeds with the current (still-valid, since the refresh fires before expiry) token. The refresh runs over the host's own egress and trust store, never through this proxy, and no token is ever logged. (Harnesses that still carry their token in-guest refresh there and carry no `refresh` block.)

This redaction currently covers **claude-code**. `codex` and `opencode` keep mounting their token for now (codex's non-secret account id lives in the same file; opencode is multi-provider with API-key providers that aren't injected) -- they still benefit from host-side injection but their cred files are not yet redacted.

### In-VM login (per-instance, isolated)

A user can run `/login` **inside** a guest; it works, **persists per-instance**, and never touches the host's credential. This falls out of the model rather than needing any capture machinery:

- **Default (placeholder present):** the guest carries the redacted stub, so its requests present `Bearer <stub>` and the addon injects the host token -- the instance **inherits** the host login.
- **After an in-guest `/login`:** the guest reaches the OAuth endpoint (`platform.claude.com`) over the default **passthrough** splice -- it is deliberately *not* terminated or injected, so the exchange is end-to-end and the guest receives and stores its **own** real tokens. That write copies up into the instance's persistent overlay upperdir (`instances/<name>/harness-overlay.img`), shadowing the redacted stub in the read-only lower. It survives reboots, and it takes **both** stub writers to keep it that way: the *launcher's* stub lives in the read-only **lower** layer (the host-only mirror `stage_overlay_source` builds), so it is simply shadowed by the upperdir copy; but the cogworx-managed reconcile (`cogbox __claude-stub`, driven by a per-instance marker) writes through the **merged** view at `/root/.claude`, i.e. into the *same* upperdir the in-guest login lives in, so shadowing cannot protect anything from it. That leg therefore refuses both to overwrite and to remove any credential at that path which does not carry cogbox's own sentinel -- so an in-guest login survives every boot and every cogworx re-drive on both legs. From then on the guest presents its **own** (non-stub) token, so `should_inject` passes it through untouched -- **host inheritance stops for that instance automatically, with no host write**. The guest holds its own refresh token too, so it self-refreshes against `platform.claude.com` directly.
- **Logout (back to the stub):** if the guest clears its credential, the merged overlay view falls back to the lower stub, so it presents the placeholder again and host inheritance resumes (placeholder present ⇒ inherit).

The boundary holds in the only direction that matters: a guest login is confined to that instance's own ext4 upperdir (the 9p lower is read-only, so overlay copy-up cannot write through to the host source), and the sole host-side write -- the addon's host-token refresh -- runs only while injecting (i.e. while the guest is still on the stub) and writes only the launching user's own canonical file, on a path the guest cannot influence. **No guest action mutates the host credential or any other instance.** (The host user can of course offline-read their own instance's image -- host-reads-own-guest, the safe direction.)

This per-instance login model currently applies to **claude-code** (the only harness with a redactor + stub identity). `codex`/`opencode` stay on the guest-carries-token path until they get redactors.

### Plugin-declared and operator-bound injection

The same terminate-tier mechanism is not limited to the built-in harnesses: a **plugin** can request injection for any host its agent talks to, and an **operator** binds the actual credential host-side. This generalizes the harness path to arbitrary bearer tokens and session cookies while preserving the credless boundary.

A plugin declares `cogboxPlugins.<attr>.inject` (see [plugins](plugins.md#credential-injection)). Crucially, a plugin can only **name** a secret and the exact host it targets -- it can never carry a value or a host-side path (the manifest is rejected at `add` time if it tries: `path`, `cred_file`, `token`, `refresh`, ... are all forbidden). Each spec names an exact `host` (no wildcard), a `style` (`bearer`, `cookie`, or `basic`; the `cookie` style also needs a `cookieName`), the secret `name`, an optional `stub` sentinel, and an optional `port` (see [non-standard ports](#non-standard-ports) -- declare it when the host is served somewhere other than 80/443, e.g. `9200` for Elasticsearch). The named specs merge into `.network.l7.inject.specs[]`:

```json
"network": { "l7": {
    "inject": { "enabled": true, "specs": [
        { "host": "api.example.com", "style": "bearer", "secret": "api-bearer", "plugin": "myplugin" },
        { "host": "es.internal", "style": "basic", "secret": "es-creds", "port": 9200, "plugin": "myplugin" },
        { "host": "app.example.com", "style": "cookie", "secret": "app-session",
          "cookieName": "app.sid", "stub": "cogbox-app-stub", "plugin": "myplugin" }
    ] },
    "rules": [ ... ]
} }
```

(`.network.l7.inject` is an object `{enabled, specs}`; the legacy bool `inject: true` -- harness injection on -- still works and is coerced to the object form the first time a verb writes inject specs.)

#### The secret store

Operators bind the real credential with `cogbox secret`, host-side, never on the command line:

```sh
cogbox secret add api-bearer --from-file ~/.secrets/api.token --audience api.example.com
cogbox secret ls
cogbox secret ls --json   # machine-readable inventory for a control plane
cogbox secret rm api-bearer
```

`cogbox secret ls --json` emits a JSON array of `{name, kind, audience, tier, bound, bound_at}` (the **value is never included**). A control plane (e.g. cogworx) reads it to show each plugin-declared inject request as bound vs unbound -- correctly reflecting the host-side store even when an operator bound the secret directly with `cogbox secret add` rather than through the UI. `audience` is `null` when unset (not injectable), `bound` is `false` when the named secret has no value file. A store that was never created prints `[]`.

The value is read from a file or stdin (never argv, which leaks to the process table) and stored at `~/.config/cogbox/secrets/<name>` (mode `0600`) alongside a `<name>.meta` sidecar recording `audience`, `kind`, `tier`, and `bound_at`. The stored value is a single line -- a bare bearer token, a `user:password` pair, or a cookie value -- interpreted according to `--kind`.

**Supported `--kind` values and their wire format:**

| Kind | `Authorization` header | Stored value |
|---|---|---|
| `bearer` (default) | `Authorization: Bearer <value>` | raw token |
| `basic` | `Authorization: Basic base64(<value>)` | `user:password` |
| `cookie` | replaces named cookie only | cookie value |

**Example -- HTTP Basic auth for an internal Elasticsearch cluster on `:9200`:**

Injection needs two things: an inject **spec** (which host + style + secret name, and -- on a non-standard port -- the `port`) and the **bound secret**. A plugin's `cogboxPlugins.inject` writes the spec for you; there is no `cogbox inject add` verb, so an operator without a plugin hand-edits `.network.l7.inject.specs[]` in the instance `config.json`:

```sh
# 1. Declare the inject spec. (A plugin does this via cogboxPlugins.inject; by hand:)
cfg=~/.config/cogbox/instances/<name>/config.json
jq '.network.l7.inject = {enabled: true,
      specs: ((.network.l7.inject.specs // []) +
        [{host: "es.internal.example.com", style: "basic", secret: "es-creds", port: 9200}])}' \
   "$cfg" > "$cfg.tmp" && mv "$cfg.tmp" "$cfg"

# 2. Bind the credential host-side (raw user:password; base64 is done at injection time).
#    The --audience is the BARE host -- no :9200 -- and must equal the spec host.
echo -n "elastic:mypassword" | cogbox secret add es-creds \
    --from-stdin --audience es.internal.example.com --kind basic

# 3. cogbox restart  (the inject spec auto-adds an `allow <host> terminate` rule and,
#    via port:9200, a funnel remap so the guest's :9200 egress reaches the proxy).
```

The guest then sends requests unauthenticated or with a placeholder, and the host proxy rewrites the `Authorization` header before the request leaves the host. The spec host, the `--audience`, and any explicit `cogbox l7 add allow` all use the **bare** host (the proxy matches the request `Host` with its port stripped); the `:9200` lives only in the spec's `port` -- see [non-standard ports](#non-standard-ports). Omit the `port` and the spec still injects on `:80`/`:443` but a `:9200` request never reaches the proxy and stays unauthenticated.

Sidecar-produced per-instance secrets use the same layout under `instances/<name>/secrets/` and shadow a global secret of the same name. Names are restricted to `[A-Za-z0-9_-]` so neither `<name>` nor `<name>.meta` can traverse out of the store.

#### Non-standard ports

The guest's web egress is funnelled into the L7 proxy by a netfilter remap that captures only TCP **:80** and **:443** -- the ports the proxy splits into its plain-HTTP and TLS entries. A host served anywhere else (Elasticsearch on **:9200**, an internal API on **:8080**, ...) would bypass the proxy entirely: the connection clears only the L4 CIDR layer and egresses untouched, so its credential is never stamped and the upstream answers `401`.

To inject on such a host, the inject spec declares a `port`:

```json
{ "host": "data-es.internal", "style": "basic", "secret": "es-creds", "port": 9200 }
```

The renderer then emits an extra funnel remap (`0.0.0.0/0:9200 -> the proxy`) so the host's `:9200` egress reaches the addon and gets injected exactly like an `:80`/`:443` host. Two consequences:

1. The funnel is **per-port and instance-wide** -- declaring `:9200` routes *all* guest TCP to `:9200` (any host) through the L7 proxy, and the proxy classifies each connection by its first bytes: a valid TLS ClientHello or an HTTP/1.x request is evaluated against the L7 rules and forwarded (injected only for the exact inject host; a non-inject HTTP/TLS host on the port is just spliced). **Anything else is dropped, fail-closed** -- a non-HTTP/non-TLS (raw binary, server-speaks-first, malformed) connection on the port never reaches an upstream dial. So this is also a *behavior change* for the port: a non-HTTP service on `:9200` that the guest could previously reach over the native L4 path is now denied. Only declare a port that genuinely serves HTTP/TLS (Elasticsearch's REST is HTTP on `:9200`; its binary transport is the separate `:9300`, unaffected).
2. The `port` is a property of the **spec**, not the secret -- the secret's `--audience` and the `cogbox l7 add allow` rule both stay the bare host.

At boot (and on the hot-reload path), the renderer resolves each spec's named secret to the store's value path and emits it with `cred_format: "raw"` -- the addon reads that file's **first non-empty line** as the credential (no dotted `token_path`, unlike the JSON-cred harness specs). It writes the inject-conf with **two fail-closed gates**:

- **unbound** -- no value bound for the named secret ⇒ no conf element. Injection stays inert (the request's stub goes upstream and fails auth) until you bind it; nothing is ever forwarded *as if* it were real auth.
- **audience mismatch** -- a spec is emitted only when the bound secret's `audience` equals the spec host. This is the gate that stops a hostile plugin from later requesting that your bound `api-bearer` be injected to `attacker.example`: you bound it for `api.example.com`, so it is injectable **only** there. A secret with no audience set is treated as not-injectable.

Inject hosts are automatically unioned into the **terminate-allow** set (a header or cookie can only be added on a MITM-terminated flow), so an inject-only plugin still activates the funnel and terminates its host -- whether injection actually fires is decided separately by the bound/audience gates above. The plugin/operator specs and the harness specs are merged into the single conf the addon reads (harness specs win a host collision). The trust an operator grants by binding a secret is surfaced at `cogbox plugin add` (the injection requests render in their own section, and a bind-checklist prints the exact `cogbox secret add` commands); the secret value itself, like the harness credentials, is host-only and never crosses into the guest.

**Reserved control-plane binds are auto-seeded.** Two secret shapes are bound by a control plane rather than declared by a plugin, so the renderer seeds their spec itself -- no `config.json` entry is needed, and none is written (the seed is a render-time overlay, so revoking is just unbinding):

- `claude-oauth` with `--kind anthropic-oauth` -- seeds `{host: api.anthropic.com, style: anthropic-oauth, secret: claude-oauth}`. The seed's ONLY gate is that **a value file exists** for the secret, so a sandbox whose owner never connected gets no spec, hence no terminate-allow for the provider host and no funnel. That gate is *presence*, not validity: a zero-byte value with no `.meta` also seeds the terminate-allow. It is safe because the injection itself is gated a layer down by the two fail-closed checks above -- such a secret has no audience, so the inject conf stays empty and nothing is ever stamped; the host is merely funnelled and terminated.
- any secret with a value file and `--kind gitlab-oauth` -- seeds a spec for its `--audience` host, but only when an l7 rule already names that host (a grant-scoped bind must never render as a whole-host allow).

The seed runs on **every** render path -- the boot render, `cogbox secret reload -n <inst>`, and the rule/plugin-mutation reload -- because both the terminate-allow and the funnel are derived from the specs, so a path that re-rendered without seeding would strip them off a running instance. (It was originally gated on a "am I an enforcing container" env signal, which made the bind inert on the VM path: the credential was bound host-side and the guest stub staged, but nothing named the secret, so the placeholder was never replaced and the harness reported *not logged in*.)

Because the funnel remaps live in `netfilter-rules` -- the file the in-`passt` LD_PRELOAD shim owns -- every one of those paths must signal **both** consumers after re-rendering: `SIGHUP` the L7 proxy (`l7-rules` + the inject conf) *and* `SIGUSR1` passt (the shim reloads its ruleset only on that signal). Signalling only the proxy leaves a connect-later bind inert on a running instance: the funnel is on disk, but the guest's `:443` keeps egressing directly, so the placeholder credential reaches the upstream and the harness stays logged out until a restart.

### Credential access under a dropped proxy uid

The store's value files are written `0600` by the uid that runs `cogbox secret add` (the control uid). Where the proxy runs as that same uid -- the container enforcer, which also owns the enforcer-private store -- reader and owner coincide and there is nothing to arrange. Where `COGBOX_PROXY_RUNAS` puts the proxy on a **dedicated uid** (so a host packet filter can select guest-originated traffic by `meta skuid`), they do not: the addon's `open()` on `cred_file` gets `EACCES`, `token_for` returns `None`, and every request on the injected host is denied with `cogbox-l7: credential unavailable` -- with the bind, the seed, the spec, the terminate-allow and the funnel all correct.

So the inject render also reconciles the store's permissions (`rules/credgrant.zig`):

- **Scope.** Exactly the value files the conf being written *names*, and nothing else in the store -- the store holds credentials for unrelated audiences the proxy has no business reading. The grant is recorded at the same statement that emits `cred_file`, so the readable set is derived from the spec set and cannot drift from it. Only a resolved store path (`<store>/<secret name>`) can ever be granted; a `cred_file` supplied by a config, a plugin manifest or an operator override never is.
- **Mechanism.** `chgrp` to the proxy's **group** plus mode `0640`. `--regid` sets the proxy's *primary* gid and `--clear-groups` drops only *supplementary* groups, so a primary-group grant survives the drop (a supplementary-group scheme would not). Group-read also keeps the grant read-only and leaves the file owned by the control uid, which still has to rewrite it when a rotated token is re-bound. The store directory gains group **search** (`+x`, never `+r`) so a granted path can be opened by name without the store becoming enumerable. The `.meta` sidecar is never granted.
- **When.** On every inject render, because binds are runtime events (`cogbox secret add -n <inst>` then `secret reload`), not boot events -- and because a re-bind is an atomic rename that resets the file's group anyway. A boot-time `chown` would cover only the sandboxes whose owner had already connected. `COGBOX_PROXY_RUNAS` therefore has to be in the environment of **control-channel execs**, not just the launcher's.
- **Revocation.** The pass first clears the group bits off every bound value file in the store, then re-grants only the named ones. Unbinding a secret, dropping a spec, an audience mismatch, or a git bind losing its grant rules all withdraw the access on the next render; there is no separate state to keep in sync.
- **Cache invalidation.** The addon caches each credential's value keyed on the value file's **mtime**, and `chmod` moves only `ctime` -- so a grant is, by itself, invisible to it. That matters because a re-bind is an atomic rename (back to `0600`) followed by a *separate* `secret reload` exec that re-renders: in between, the previous conf still names a file the proxy can no longer read, so a guest request landing there caches "unreadable" -- and with the cache key untouched by the re-grant, that host would 403 `credential unavailable` until the proxy restarted. Two things close it: the grant bumps the value file's mtime, but only on a real `0600 -> 0640` transition (a steady-state render must not, because the mtime is also the *rotation* signal the host-side refresh path reads); and the addon drops its credential caches whenever the inject conf reloads, which happens in the same render pass and so also covers a grant that failed once and succeeded on a later render.

Unset `COGBOX_PROXY_RUNAS` (container, k8s, local) means no uid split, and the whole reconciliation is skipped -- store permissions come out of a render byte-for-byte as `secret add` left them.

### What it does and does not protect

**Eliminated:** theft of the long-lived **refresh token** (it never enters the guest), account takeover via a stolen credential file reused off-box, and any persistence beyond the instance lifetime -- only short-lived access tokens are ever injected, host-side, into headers the guest cannot read.

**Not changed:** the guest still holds a **live, authenticated channel** to the provider while the instance runs. A compromised agent can still burn quota / cost and exfiltrate data through the model itself. Credential injection is a credential-*confidentiality* control, not a capability-*confinement* control; pair it with the L4/L7 egress rules, plus rate/cost limits and output monitoring. Note also that terminating a provider host means the **host process sees the plaintext** of that harness's model traffic (your box, never persisted) and that HTTP/2 is downgraded to HTTP/1.1 for that host.
