"""cogbox L7 terminate-tier enforcement addon for mitmproxy.

The Zig proxy (cogbox __l7proxy) hands terminate-marked hosts to mitmproxy
over SOCKS5, carrying the already-SSRF/CIDR-VETTED upstream IP as the CONNECT
target. mitmproxy mints a per-SNI leaf from the instance CA and decrypts; this
addon then, on every decrypted request:

  1. forces the upstream TLS SNI to the client's negotiated SNI -- we were
     handed a bare IP, so without this mitmproxy would send the IP as SNI and
     upstream cert validation would fail;
  2. enforces Host == SNI (anti-fronting / HTTP-2 cross-authority);
  3. allow/deny by host pattern + boundary-aware path prefix, first match,
     default deny -- mirroring filter.zig's L7RuleSet semantics exactly.

Separately, on the upstream TLS handshake (`tls_start_server`), it disables
proxy->upstream cert verification for hosts explicitly marked `insecure` in
the rules -- the operator's per-host equivalent of `curl -k` on the
proxy<->upstream leg, for internal services with self-signed/mismatched certs.
Every other host keeps the default verification (fail closed).

SSRF/CIDR vetting is NOT repeated here; it stayed authoritative in the Zig
proxy. Rules are read from the same l7-rules file (path in COGBOX_L7_RULES)
and hot-reloaded on mtime change, so `cogbox l7 add/del` takes effect without
restarting mitmproxy.
"""

import os
import urllib.parse

try:
    from mitmproxy import http, ctx
except ImportError:  # allow importing the pure helpers without mitmproxy
    http = None
    ctx = None

RULES_PATH = os.environ.get("COGBOX_L7_RULES", "")


class Rules:
    def __init__(self):
        self.mtime = None
        self.mode_terminate = False
        self.rules = []  # list of (action, host_pattern, path_or_None, insecure_bool)

    def maybe_reload(self):
        try:
            mtime = os.stat(RULES_PATH).st_mtime
        except OSError:
            self.rules, self.mode_terminate, self.mtime = [], False, None
            return
        if mtime == self.mtime:
            return
        self.mtime = mtime
        rules, mode_t = [], False
        try:
            with open(RULES_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    toks = line.split()
                    if toks[0] == "mode":
                        mode_t = len(toks) > 1 and toks[1] == "terminate"
                        continue
                    if toks[0] not in ("allow", "deny") or len(toks) < 2:
                        continue
                    action, host, path, insecure = toks[0], toks[1], None, False
                    for tk in toks[2:]:
                        if tk.startswith("/"):
                            path = tk
                        elif tk == "insecure":
                            insecure = True
                    rules.append((action, host, path, insecure))
        except OSError:
            pass
        self.rules, self.mode_terminate = rules, mode_t


def host_match(pattern, host):
    host = host.rstrip(".").lower()
    pattern = pattern.lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # >=1 subdomain label, matched at a dot boundary
        return host.endswith("." + suffix) and len(host) > len(suffix) + 1
    return host == pattern


def path_match(rule_path, req_path):
    # Boundary-aware left-anchored prefix (mirrors filter.pathPrefixMatches).
    if not req_path.startswith(rule_path):
        return False
    if len(req_path) == len(rule_path):
        return True
    if rule_path.endswith("/"):
        return True
    return req_path[len(rule_path)] == "/"


def normalize_path(p):
    # Strip query/fragment, percent-decode, collapse '.'/'..'/empty segments
    # (mirrors l7proxy/http.zig normalizePath, incl. trailing-slash handling).
    p = p.split("?", 1)[0].split("#", 1)[0]
    p = urllib.parse.unquote(p)
    if not p.startswith("/"):
        p = "/" + p
    trailing = p.endswith("/")
    parts = []
    for seg in p.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    if not parts:
        return "/"
    out = "/" + "/".join(parts)
    if trailing:
        out += "/"
    return out


def evaluate(rules, host, path):
    h = host.rstrip(".")
    for action, pattern, rpath, _insecure in rules.rules:
        if not host_match(pattern, h):
            continue
        if rpath is not None and not path_match(rpath, path):
            continue
        return action
    return "deny"


def host_insecure(rules, host):
    """True if `host` matches an `allow` rule flagged insecure-upstream.

    Upstream cert verification is a host-level property (it governs the
    proxy<->upstream TLS leg, independent of the request path), so we match on
    the host pattern only -- the `request` hook already enforced allow + path.
    """
    h = host.rstrip(".")
    for action, pattern, rpath, insecure in rules.rules:
        if action == "allow" and insecure and host_match(pattern, h):
            return True
    return False


RULES = Rules()


def _deny(flow, msg):
    flow.response = http.Response.make(
        403, ("cogbox-l7: " + msg + "\n").encode(), {"Content-Type": "text/plain"}
    )


def request(flow):
    RULES.maybe_reload()

    sni = flow.client_conn.sni
    # We connected to the upstream by vetted IP, so use the client's SNI for
    # the upstream TLS handshake + cert validation.
    if sni:
        flow.server_conn.sni = sni

    host = flow.request.pretty_host
    if sni and host and sni.rstrip(".").lower() != host.rstrip(".").lower():
        _deny(flow, "host/sni mismatch")
        return

    path = normalize_path(flow.request.path)
    if evaluate(RULES, host, path) != "allow":
        _deny(flow, "denied")
        return


def tls_start_server(data):
    """Per-host upstream cert verification toggle.

    mitmproxy's built-in TlsConfig decides proxy->upstream verification purely
    from the global `ssl_insecure` option, and -- because ScriptLoader is
    registered ahead of TlsConfig -- this hook runs FIRST, before that option
    is read. We flip it per connection keyed on the client SNI so that only
    hosts explicitly marked `insecure` skip upstream verification; every other
    flow keeps the default VERIFY_PEER. We (re)assign on every call, so the
    toggle never leaks to a subsequent connection.

    Fail-safe: if a future mitmproxy ever ran this hook AFTER TlsConfig, the
    option flip would simply have no effect on the already-built connection --
    insecure hosts would 502 (verification stays on), never silently weaker.
    """
    if ctx is None:
        return
    RULES.maybe_reload()
    client = data.context.client if data.context else None
    sni = (client.sni if client else None) or getattr(data.conn, "sni", None) or ""
    want = bool(sni) and host_insecure(RULES, sni)
    if ctx.options.ssl_insecure != want:
        ctx.options.ssl_insecure = want
