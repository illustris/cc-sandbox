#!/usr/bin/env python3
"""Parity unit tests for the mitmproxy L7 addon's pure helpers.

These must match filter.zig's L7 semantics (host pattern, boundary-aware path
prefix, path normalization) so HTTPS-terminate enforcement behaves identically
to the Zig proxy's HTTP/passthrough enforcement. Run: python3 test_l7_addon.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON = os.path.join(HERE, "..", "l7-mitm-addon.py")
spec = importlib.util.spec_from_file_location("l7addon", ADDON)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


# host_match: exact / *.suffix / *
check(m.host_match("vhost-a.test", "vhost-a.test"), "exact")
check(m.host_match("vhost-a.test", "VHOST-A.TEST"), "case-insensitive")
check(m.host_match("vhost-a.test", "vhost-a.test."), "trailing dot")
check(not m.host_match("vhost-a.test", "vhost-b.test"), "sibling denied")
check(m.host_match("*.cdn.test", "x.cdn.test"), "wildcard one label")
check(m.host_match("*.cdn.test", "a.b.cdn.test"), "wildcard multi label")
check(not m.host_match("*.cdn.test", "cdn.test"), "wildcard needs subdomain")
check(not m.host_match("*.cdn.test", "evilcdn.test"), "wildcard boundary")
check(m.host_match("*", "anything.test"), "bare star")

# path_match: boundary-aware prefix
check(m.path_match("/api", "/api"), "path eq")
check(m.path_match("/api", "/api/"), "path slash boundary")
check(m.path_match("/api", "/api/v1"), "path subpath")
check(not m.path_match("/api", "/apifoo"), "path no false prefix")
check(m.path_match("/v1/", "/v1/x"), "path trailing slash rule")
check(not m.path_match("/v1/", "/v1"), "path trailing slash strict")

# normalize_path: percent-decode + dot-segment collapse + query strip
check(m.normalize_path("/v1/x?q=1") == "/v1/x", "strip query")
check(m.normalize_path("/api/../%61dmin/./x") == "/admin/x", "normalize+decode")
check(m.normalize_path("/v1/%2e%2e/secret") == "/secret", "%2e%2e traversal")
check(m.normalize_path("/v1/") == "/v1/", "trailing slash preserved")
check(m.normalize_path("//a") == "/a", "collapse double slash")
check(m.normalize_path("/../..") == "/", "pop past root")


# evaluate: first-match, default-deny, path-gated
class _R:
    def __init__(self, rules, mode_terminate=False):
        self.rules = rules
        self.mode_terminate = mode_terminate


rs = _R([
    ("allow", "api.example.com", "/v1/", False),
    ("allow", "plain.test", None, False),
    ("deny", "*", None, False),
])
check(m.evaluate(rs, "api.example.com", "/v1/x") == "allow", "path allow")
check(m.evaluate(rs, "api.example.com", "/v2/x") == "deny", "path deny")
check(m.evaluate(rs, "plain.test", "/anything") == "allow", "host allow")
check(m.evaluate(rs, "other.test", "/") == "deny", "default deny via catch-all")
check(m.evaluate(_R([("allow", "only.test", None, False)]), "x.test", "/") == "deny", "default deny")

# host_insecure: only allow-rules flagged insecure match; host-level (path-independent)
ri = _R([
    ("allow", "internal.svc", "/api/", True),
    ("allow", "secure.svc", None, False),
    ("deny", "nope.svc", None, True),
    ("allow", "*.lab.test", None, True),
])
check(m.host_insecure(ri, "internal.svc"), "insecure host flagged")
check(m.host_insecure(ri, "internal.svc."), "insecure host flagged (trailing dot)")
check(not m.host_insecure(ri, "secure.svc"), "non-insecure host not flagged")
check(not m.host_insecure(ri, "nope.svc"), "deny rule never insecure-allows")
check(not m.host_insecure(ri, "unlisted.svc"), "unlisted host not insecure")
check(m.host_insecure(ri, "box.lab.test"), "insecure wildcard host")

if fails:
    print("FAIL:", *fails, sep="\n  ")
    sys.exit(1)
print("all addon parity tests passed")
