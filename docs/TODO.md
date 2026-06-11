# cogbox L7 -- backlog / TODO

Follow-ups discovered while building and testing the L7 (vhost) filtering layer.

## Per-instance L7 proxy lifecycle (high)

The host-side L7 stack (`cogbox __l7proxy` + the mitmproxy terminate backend)
currently binds fixed host-wide loopback ports (18443 TLS funnel, 18081 HTTP
funnel, 18444 mitmproxy SOCKS5). Consequences:

- Only ONE L7-enabled instance can run per host; a second instance's proxy
  fails to bind (`error: Bind`).
- On bind failure the launch only *warns* ("guest 80/443 will be blocked") and
  continues. This fails OPEN, not closed: the funnel still rewrites the guest's
  80/443 to `127.0.0.1:18443`, which is owned by the OTHER instance's proxy --
  so the guest's traffic is silently evaluated under a DIFFERENT instance's
  L7/L4 policy (cross-instance policy bleed).

Build a proper per-instance harness that starts/stops the L7 proxy + mitmproxy
as managed processes tied to the instance lifecycle, and **fails closed** when
the proxy can't bind (abort the start / don't inject the funnel remaps), never
leaving the funnel pointed at another instance's listener.

## Per-instance proxy addressing (high)

Give each instance its own L7 proxy endpoints so multiple L7-enabled instances
coexist. Prefer **Unix domain sockets** (a per-instance path under the runtime
dir) over TCP loopback ports -- no port-allocation bookkeeping, no collisions,
and naturally scoped to the instance. Thread the socket path through the rules
renderer (the remap target), the proxy listener, the shim's SOCKS dialer, and
the mitmproxy backend handoff.

## Terminate: upstream cert verification opt-out (medium)

(surfaced 2026-06-11) A terminate host whose upstream presents a
mismatched/self-signed cert returns mitmproxy's `502 Bad Gateway --
Certificate verify failed`, because mitmproxy verifies the upstream cert
against the SNI and the guest's `-k` only covers the guest<->proxy leg (which
is our minted leaf), not the proxy<->upstream leg. Common for internal
services. Add an opt-out (per-host `--insecure-upstream`, or a per-instance
toggle) that skips upstream verification for explicitly-marked hosts -- the
operator's equivalent of the `-k` they'd use directly. Default stays verify
(fail closed).

## `cogbox stop` on a stopped instance (low)

`cogbox stop` against an instance that isn't running should clearly report that
it isn't running (message + exit code 3, matching `status`), rather than
silently succeeding.
