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

SSRF/CIDR vetting is NOT repeated here; it stayed authoritative in the Zig
proxy. Rules are read from the same l7-rules file (path in COGBOX_L7_RULES)
and hot-reloaded on mtime change, so `cogbox l7 add/del` takes effect without
restarting mitmproxy.
"""

import os
import urllib.parse

try:
    from mitmproxy import http
except ImportError:  # allow importing the pure helpers without mitmproxy
    http = None

RULES_PATH = os.environ.get("COGBOX_L7_RULES", "")


class Rules:
    def __init__(self):
        self.mtime = None
        self.mode_terminate = False
        self.rules = []  # list of (action, host_pattern, path_or_None)

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
                    action, host, path = toks[0], toks[1], None
                    for tk in toks[2:]:
                        if tk.startswith("/"):
                            path = tk
                    rules.append((action, host, path))
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
    for action, pattern, rpath in rules.rules:
        if not host_match(pattern, h):
            continue
        if rpath is not None and not path_match(rpath, path):
            continue
        return action
    return "deny"


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
