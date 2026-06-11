const std = @import("std");

pub const Action = enum {
	allow,
	deny,
};

pub const Proto = enum {
	any,
	tcp,
	udp,
};

pub const IpAddr = union(enum) {
	ipv4: [4]u8,
	ipv6: [16]u8,
};

pub const Rule = struct {
	proto: Proto = .any,
	network: IpAddr,
	prefix_len: u8,
	port: u16 = 0, // 0 == "any port"
	action: Action,
};

pub const RemapTarget = struct {
	proto: Proto, // tcp or udp; never .any
	addr: IpAddr,
	port: u16,
};

pub const RemapRule = struct {
	proto: Proto, // must be tcp or udp (no .any)
	network: IpAddr,
	prefix_len: u8,
	port: u16, // explicit; 0 disallowed
	target: RemapTarget,
};

pub const max_rules = 256;
pub const max_remap_rules = 64;
pub const max_dns_rules = 256;
pub const max_dns_pattern_len: u8 = 253; // RFC 1035 FQDN length cap

pub const DnsPatternKind = enum { exact, left_wildcard, any };

pub const DnsPattern = struct {
	kind: DnsPatternKind,
	buf: [max_dns_pattern_len]u8 = undefined,
	len: u8 = 0,

	pub fn slice(self: *const DnsPattern) []const u8 {
		return self.buf[0..self.len];
	}
};

pub const DnsRule = struct {
	pattern: DnsPattern,
	action: Action,
};

pub const RuleSet = struct {
	rules: [max_rules]Rule = undefined,
	len: usize = 0,

	// Remap rules consulted by the shim's TCP connect() wrapper to
	// rewrite outbound destinations. Walked AFTER the CIDR allow/deny
	// pass, so a remap hit implicitly says "allow but divert".
	remap_rules: [max_remap_rules]RemapRule = undefined,
	remap_len: usize = 0,

	// DNS rules consulted by the libc-resolver wrappers in the shim.
	// Independent of CIDR rules: a DNS allow does not imply IP allow.
	dns_rules: [max_dns_rules]DnsRule = undefined,
	dns_len: usize = 0,
	dns_default: Action = .allow,

	/// Evaluate a destination (proto, addr, port) against the CIDR rules.
	/// Callers that don't know the protocol may pass `.any`; rules with an
	/// explicit proto qualifier won't match a `.any` query.
	pub fn evaluate(self: *const RuleSet, proto: Proto, addr: IpAddr, port: u16) Action {
		// Implicit: allow DNS (port 53) -- checked first so DNS to
		// loopback resolvers (e.g. 127.0.0.53 systemd-resolved) works.
		if (port == 53) return .allow;

		// Implicit: deny loopback -- passt maps its gateway and the
		// host's IP to 127.0.0.1, so allowing loopback would expose
		// all host services to the sandbox. The remap path bypasses
		// this check because it never calls evaluate() against the
		// rewritten destination.
		if (isLoopback(addr)) return .deny;

		const check_addr = normalizeMapped(addr);

		// Walk user rules in order, first match wins
		for (self.rules[0..self.len]) |rule| {
			if (ruleMatches(rule, proto, check_addr, port)) {
				return rule.action;
			}
		}

		// Default: deny
		return .deny;
	}

	/// If a remap rule matches the (proto, addr, port) tuple, return its
	/// target. Otherwise null. Caller is expected to have already passed
	/// the CIDR check -- this method does not consult `rules`.
	pub fn evaluateRemap(self: *const RuleSet, proto: Proto, addr: IpAddr, port: u16) ?RemapTarget {
		const check_addr = normalizeMapped(addr);
		for (self.remap_rules[0..self.remap_len]) |r| {
			if (remapMatches(r, proto, check_addr, port)) return r.target;
		}
		return null;
	}

	/// Evaluate a hostname against the DNS rule table. The host may carry a
	/// trailing `.` (root label) -- it is stripped before matching.
	pub fn evaluateDns(self: *const RuleSet, host: []const u8) Action {
		var h = host;
		if (h.len > 0 and h[h.len - 1] == '.') h = h[0 .. h.len - 1];
		for (self.dns_rules[0..self.dns_len]) |r| {
			if (matchDnsPattern(r.pattern, h)) return r.action;
		}
		return self.dns_default;
	}
};

fn matchDnsPattern(p: DnsPattern, host: []const u8) bool {
	switch (p.kind) {
		.any => return true,
		.exact => return std.ascii.eqlIgnoreCase(p.slice(), host),
		.left_wildcard => {
			const suffix = p.slice();
			// `*.example.com` must match >=1 subdomain label, so the host
			// needs at least one char and a `.` before the suffix.
			if (host.len <= suffix.len + 1) return false;
			const sep_idx = host.len - suffix.len - 1;
			if (host[sep_idx] != '.') return false;
			return std.ascii.eqlIgnoreCase(host[sep_idx + 1 ..], suffix);
		},
	}
}

/// Validate a hostname-shaped string. Permissive enough for real-world
/// names (LDH labels), strict enough to reject empty labels, leading/
/// trailing dots, and stray punctuation.
pub fn isValidHostName(s: []const u8) bool {
	if (s.len == 0 or s.len > max_dns_pattern_len) return false;
	if (s[0] == '.' or s[s.len - 1] == '.') return false;
	var prev_dot = true;
	for (s) |c| {
		switch (c) {
			'a'...'z', 'A'...'Z', '0'...'9', '_' => prev_dot = false,
			'-' => {
				if (prev_dot) return false; // label can't start with hyphen
				prev_dot = false;
			},
			'.' => {
				if (prev_dot) return false; // empty label
				prev_dot = true;
			},
			else => return false,
		}
	}
	return true;
}

/// Parse a DNS pattern. Returns null for malformed input.
///   `*`             -> .any
///   `*.example.com` -> .left_wildcard("example.com")
///   `example.com`   -> .exact("example.com")
///   anything with `*` not at the leftmost position is rejected.
pub fn parseDnsPattern(s: []const u8) ?DnsPattern {
	const t = std.mem.trim(u8, s, " \t");
	if (t.len == 0) return null;
	if (std.mem.eql(u8, t, "*")) {
		return .{ .kind = .any, .len = 0 };
	}
	if (std.mem.startsWith(u8, t, "*.")) {
		const rest = t[2..];
		if (std.mem.indexOfScalar(u8, rest, '*') != null) return null;
		if (!isValidHostName(rest)) return null;
		var p: DnsPattern = .{ .kind = .left_wildcard, .len = @intCast(rest.len) };
		@memcpy(p.buf[0..rest.len], rest);
		return p;
	}
	if (std.mem.indexOfScalar(u8, t, '*') != null) return null; // right-anchor or middle
	if (!isValidHostName(t)) return null;
	var p: DnsPattern = .{ .kind = .exact, .len = @intCast(t.len) };
	@memcpy(p.buf[0..t.len], t);
	return p;
}

pub const DnsLine = struct {
	action: Action,
	pattern: DnsPattern,
};

/// Parse a single `dns ...` line body (i.e. text after the `dns ` prefix).
/// Recognises:
///   `default allow` / `default deny`  -> returns null + writes to *default_out (if non-null)
///   `allow PATTERN` / `deny PATTERN`  -> returns DnsLine
/// Returns null on malformed input, on the `default` form, or on empty input.
pub fn parseDnsBody(body: []const u8, default_out: ?*Action) ?DnsLine {
	const t = std.mem.trim(u8, body, " \t");
	if (t.len == 0) return null;
	if (std.mem.startsWith(u8, t, "default ")) {
		const v = std.mem.trim(u8, t[8..], " \t");
		if (default_out) |out| {
			if (std.mem.eql(u8, v, "allow")) out.* = .allow;
			if (std.mem.eql(u8, v, "deny")) out.* = .deny;
		}
		return null;
	}
	var action: Action = undefined;
	var rest: []const u8 = undefined;
	if (std.mem.startsWith(u8, t, "allow ")) {
		action = .allow;
		rest = t[6..];
	} else if (std.mem.startsWith(u8, t, "deny ")) {
		action = .deny;
		rest = t[5..];
	} else {
		return null;
	}
	const pat = parseDnsPattern(rest) orelse return null;
	return .{ .action = action, .pattern = pat };
}

const ipv6_loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const ipv4_mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

pub fn isIpv4Mapped(ip: [16]u8) bool {
	return std.mem.eql(u8, ip[0..12], &ipv4_mapped_prefix);
}

fn normalizeMapped(addr: IpAddr) IpAddr {
	return switch (addr) {
		.ipv6 => |ip| if (isIpv4Mapped(ip))
			.{ .ipv4 = .{ ip[12], ip[13], ip[14], ip[15] } }
		else
			addr,
		.ipv4 => addr,
	};
}

/// True for loopback destinations (127.0.0.0/8, ::1, and the IPv4-mapped
/// form of 127/8). Lifted out of `evaluate()` so the shim's connect()
/// reorder can reuse it: a remap rule's broad LHS (e.g. 0.0.0.0/0:443)
/// must NOT divert the guest's own loopback probes.
pub fn isLoopback(addr: IpAddr) bool {
	return switch (normalizeMapped(addr)) {
		.ipv4 => |ip| ip[0] == 127,
		.ipv6 => |ip| std.mem.eql(u8, &ip, &ipv6_loopback),
	};
}

// The L7 proxy's NON-OVERRIDABLE hard floor: addresses it must never dial no
// matter what the instance rules say. The proxy runs OUTSIDE the LD_PRELOAD
// shim, so its host-side getaddrinfo()+connect() faces no L4 policy except
// what we enforce here plus the instance CIDR re-check.
//
// This floor is deliberately MINIMAL -- only targets that are never a
// legitimate egress destination and are the classic SSRF pivots: loopback,
// "this-network", and link-local (which includes cloud metadata
// 169.254.169.254). Private ranges (RFC1918 / CGNAT / ULA) are NOT here: they
// are blocked by the instance's seeded default-deny rules, but a user can
// legitimately reach an internal vhost on a private LB by adding an explicit
// `allow` -- exactly as they would for a direct L4 connection. Deferring those
// to the CIDR re-check makes the proxy's egress identical to L4 for them,
// rather than strictly more restrictive.
const hard_blocked_v4 = [_]struct { net: [4]u8, prefix: u8 }{
	.{ .net = .{ 0, 0, 0, 0 }, .prefix = 8 }, // "this network" (0.0.0.0/8, localhost alias on Linux)
	.{ .net = .{ 127, 0, 0, 0 }, .prefix = 8 }, // loopback
	.{ .net = .{ 169, 254, 0, 0 }, .prefix = 16 }, // link-local incl. cloud metadata 169.254.169.254
};

/// True if the L7 proxy must refuse to dial this resolved address regardless
/// of instance rules. Folds IPv4-mapped IPv6 into IPv4 first so
/// `::ffff:169.254.169.254` is caught. Private ranges are intentionally NOT
/// hard-blocked -- they are governed by the instance CIDR policy (see above).
pub fn isHardBlocked(addr: IpAddr) bool {
	switch (normalizeMapped(addr)) {
		.ipv4 => |ip| {
			for (hard_blocked_v4) |b| {
				if (ipv4Matches(b.net, ip, b.prefix)) return true;
			}
			return false;
		},
		.ipv6 => |ip| {
			if (std.mem.eql(u8, &ip, &ipv6_loopback)) return true; // ::1
			if (std.mem.eql(u8, &ip, &([_]u8{0} ** 16))) return true; // :: unspecified
			if (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) return true; // fe80::/10 link-local
			return false;
		},
	}
}

fn cidrContains(network: IpAddr, prefix_len: u8, addr: IpAddr) bool {
	return switch (network) {
		.ipv4 => |net| switch (addr) {
			.ipv4 => |ip| ipv4Matches(net, ip, prefix_len),
			.ipv6 => false,
		},
		.ipv6 => |net| switch (addr) {
			.ipv6 => |ip| ipv6Matches(net, ip, prefix_len),
			.ipv4 => false,
		},
	};
}

fn cidrMatches(rule: Rule, addr: IpAddr) bool {
	return cidrContains(rule.network, rule.prefix_len, addr);
}

fn ruleMatches(rule: Rule, proto: Proto, addr: IpAddr, port: u16) bool {
	if (rule.proto != .any and rule.proto != proto) return false;
	if (rule.port != 0 and rule.port != port) return false;
	return cidrContains(rule.network, rule.prefix_len, addr);
}

fn remapMatches(r: RemapRule, proto: Proto, addr: IpAddr, port: u16) bool {
	if (r.proto != proto) return false;
	if (r.port != port) return false;
	return cidrContains(r.network, r.prefix_len, addr);
}

fn ipv4Matches(net: [4]u8, ip: [4]u8, prefix_len: u8) bool {
	if (prefix_len == 0) return true;
	if (prefix_len > 32) return false;
	if (prefix_len == 32) return std.mem.eql(u8, &net, &ip);

	const net_u32 = std.mem.readInt(u32, &net, .big);
	const ip_u32 = std.mem.readInt(u32, &ip, .big);
	const shift: u5 = @intCast(32 - prefix_len);
	const mask: u32 = ~@as(u32, 0) << shift;
	return (net_u32 & mask) == (ip_u32 & mask);
}

fn ipv6Matches(net: [16]u8, ip: [16]u8, prefix_len: u8) bool {
	if (prefix_len == 0) return true;
	if (prefix_len > 128) return false;

	const full_bytes: usize = prefix_len / 8;
	const remaining_bits: u3 = @intCast(prefix_len % 8);

	if (!std.mem.eql(u8, net[0..full_bytes], ip[0..full_bytes])) return false;

	if (remaining_bits > 0 and full_bytes < 16) {
		const shift: u3 = @intCast(8 - @as(u4, remaining_bits));
		const mask: u8 = ~@as(u8, 0) << shift;
		if ((net[full_bytes] & mask) != (ip[full_bytes] & mask)) return false;
	}

	return true;
}

/// Parse a single allow/deny rule line. Accepted forms:
///   allow|deny CIDR                       (proto=any, port=any)
///   allow|deny tcp|udp CIDR               (port=any)
///   allow|deny CIDR:PORT                  (proto=any)
///   allow|deny tcp|udp CIDR:PORT
/// IPv6 CIDRs and port suffixes on IPv6 are not supported in v1.
pub fn parseLine(line: []const u8) ?Rule {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;

	var action: Action = undefined;
	var rest: []const u8 = undefined;

	if (std.mem.startsWith(u8, trimmed, "allow ")) {
		action = .allow;
		rest = trimmed[6..];
	} else if (std.mem.startsWith(u8, trimmed, "deny ")) {
		action = .deny;
		rest = trimmed[5..];
	} else {
		return null;
	}

	const pcp = parseProtoCidrPort(rest, .{ .require_cidr_slash = true }) orelse return null;
	return .{
		.proto = pcp.proto,
		.network = pcp.network,
		.prefix_len = pcp.prefix_len,
		.port = pcp.port,
		.action = action,
	};
}

const ProtoCidrPort = struct {
	proto: Proto,
	network: IpAddr,
	prefix_len: u8,
	port: u16, // 0 == not specified
};

const ParseOpts = struct {
	require_proto: bool = false,
	require_cidr_slash: bool = false,
};

/// Parse the trailing form `[tcp|udp ] CIDR[:port]`. When
/// `require_cidr_slash` is false, a bare IP without `/N` defaults to /32
/// (useful for remap targets).
fn parseProtoCidrPort(s: []const u8, opts: ParseOpts) ?ProtoCidrPort {
	var rest = std.mem.trim(u8, s, " \t");

	var proto: Proto = .any;
	if (std.mem.startsWith(u8, rest, "tcp ")) {
		proto = .tcp;
		rest = std.mem.trim(u8, rest[4..], " \t");
	} else if (std.mem.startsWith(u8, rest, "udp ")) {
		proto = .udp;
		rest = std.mem.trim(u8, rest[4..], " \t");
	}
	if (opts.require_proto and proto == .any) return null;

	// IPv6 path: any textual IPv6 address carries >=2 colons. v1 supports
	// PORT-LESS IPv6 CIDRs only (used for the L7 v6 fail-closed denies, e.g.
	// `deny tcp ::/0`); bracketed IPv6+port is not supported.
	if (std.mem.count(u8, rest, ":") >= 2) {
		var prefix6: u8 = 128;
		var ip6_str: []const u8 = rest;
		if (std.mem.indexOfScalar(u8, rest, '/')) |sp| {
			ip6_str = rest[0..sp];
			prefix6 = std.fmt.parseInt(u8, rest[sp + 1 ..], 10) catch return null;
		} else if (opts.require_cidr_slash) {
			return null;
		}
		if (prefix6 > 128) return null;
		const ipv6 = parseIpv6(ip6_str) orelse return null;
		return .{ .proto = proto, .network = .{ .ipv6 = ipv6 }, .prefix_len = prefix6, .port = 0 };
	}

	// Split off `:port` if present. The IPv4 path treats any single colon as
	// the port separator.
	var addr_part: []const u8 = rest;
	var port: u16 = 0;
	if (std.mem.indexOfScalar(u8, rest, ':')) |colon| {
		// If there's more than one colon (IPv6 textual form), bail out.
		if (std.mem.lastIndexOfScalar(u8, rest, ':').? != colon) return null;
		addr_part = rest[0..colon];
		const port_str = std.mem.trim(u8, rest[colon + 1 ..], " \t");
		port = std.fmt.parseInt(u16, port_str, 10) catch return null;
		if (port == 0) return null; // port 0 reserved for "any"
	}

	var prefix_len: u8 = 32;
	var ip_str: []const u8 = addr_part;
	if (std.mem.indexOfScalar(u8, addr_part, '/')) |sp| {
		ip_str = addr_part[0..sp];
		prefix_len = std.fmt.parseInt(u8, addr_part[sp + 1 ..], 10) catch return null;
	} else if (opts.require_cidr_slash) {
		return null;
	}
	if (prefix_len > 32) return null;

	const ipv4 = parseIpv4(ip_str) orelse return null;
	return .{
		.proto = proto,
		.network = .{ .ipv4 = ipv4 },
		.prefix_len = prefix_len,
		.port = port,
	};
}

/// Parse a single `remap` rule line:
///   remap PROTO CIDR:PORT -> PROTO IP[:PORT]
/// v1 restricts both sides to `tcp` and remap targets to single hosts
/// (/32). Returns null for malformed input.
pub fn parseRemapLine(line: []const u8) ?RemapRule {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;
	if (!std.mem.startsWith(u8, trimmed, "remap ")) return null;
	const body = trimmed[6..];

	const arrow = std.mem.indexOf(u8, body, "->") orelse return null;
	const lhs = std.mem.trim(u8, body[0..arrow], " \t");
	const rhs = std.mem.trim(u8, body[arrow + 2 ..], " \t");

	const lhs_p = parseProtoCidrPort(lhs, .{ .require_proto = true, .require_cidr_slash = true }) orelse return null;
	if (lhs_p.port == 0) return null;
	if (lhs_p.proto != .tcp) return null; // v1: tcp -> tcp only

	const rhs_p = parseProtoCidrPort(rhs, .{ .require_proto = true }) orelse return null;
	if (rhs_p.port == 0) return null;
	if (rhs_p.prefix_len != 32) return null; // single host
	if (rhs_p.proto != .tcp) return null;

	return .{
		.proto = lhs_p.proto,
		.network = lhs_p.network,
		.prefix_len = lhs_p.prefix_len,
		.port = lhs_p.port,
		.target = .{
			.proto = rhs_p.proto,
			.addr = rhs_p.network,
			.port = rhs_p.port,
		},
	};
}

/// Parse a textual IPv6 address (with optional `::` compression) into 16
/// bytes. Embedded IPv4 (`::ffff:1.2.3.4`) is not accepted in v1. Returns
/// null on malformed input.
pub fn parseIpv6(s: []const u8) ?[16]u8 {
	var result = [_]u8{0} ** 16;
	if (std.mem.indexOf(u8, s, "::")) |dc| {
		const head = s[0..dc];
		const tail = s[dc + 2 ..];
		if (std.mem.indexOf(u8, tail, "::") != null) return null; // only one ::
		var front: [8]u16 = undefined;
		var fcount: usize = 0;
		if (head.len > 0) fcount = parseV6Groups(head, &front) orelse return null;
		var back: [8]u16 = undefined;
		var bcount: usize = 0;
		if (tail.len > 0) bcount = parseV6Groups(tail, &back) orelse return null;
		if (fcount + bcount > 8) return null; // :: must elide >=1 group... unless whole-zero
		var i: usize = 0;
		while (i < fcount) : (i += 1) {
			result[i * 2] = @intCast(front[i] >> 8);
			result[i * 2 + 1] = @intCast(front[i] & 0xff);
		}
		const back_start = 8 - bcount;
		i = 0;
		while (i < bcount) : (i += 1) {
			const idx = back_start + i;
			result[idx * 2] = @intCast(back[i] >> 8);
			result[idx * 2 + 1] = @intCast(back[i] & 0xff);
		}
		return result;
	}
	var groups: [8]u16 = undefined;
	const n = parseV6Groups(s, &groups) orelse return null;
	if (n != 8) return null;
	var i: usize = 0;
	while (i < 8) : (i += 1) {
		result[i * 2] = @intCast(groups[i] >> 8);
		result[i * 2 + 1] = @intCast(groups[i] & 0xff);
	}
	return result;
}

fn parseV6Groups(s: []const u8, out: *[8]u16) ?usize {
	var n: usize = 0;
	var it = std.mem.splitScalar(u8, s, ':');
	while (it.next()) |grp| {
		if (n >= 8) return null;
		if (grp.len == 0 or grp.len > 4) return null;
		if (std.mem.indexOfScalar(u8, grp, '.') != null) return null; // no embedded v4
		out[n] = std.fmt.parseInt(u16, grp, 16) catch return null;
		n += 1;
	}
	return n;
}

pub fn parseIpv4(s: []const u8) ?[4]u8 {
	var result: [4]u8 = undefined;
	var octet_idx: usize = 0;
	var iter = std.mem.splitScalar(u8, s, '.');

	while (iter.next()) |part| {
		if (octet_idx >= 4) return null;
		result[octet_idx] = std.fmt.parseInt(u8, part, 10) catch return null;
		octet_idx += 1;
	}

	if (octet_idx != 4) return null;
	return result;
}

/// Parse a multi-line rules string into a RuleSet.
pub fn parseRules(content: []const u8) RuleSet {
	var ruleset = RuleSet{};
	var lines = std.mem.splitScalar(u8, content, '\n');

	while (lines.next()) |line| {
		const trimmed = std.mem.trim(u8, line, " \t\r\n");
		if (trimmed.len == 0 or trimmed[0] == '#') continue;

		if (std.mem.startsWith(u8, trimmed, "dns ")) {
			const body = trimmed[4..];
			if (parseDnsBody(body, &ruleset.dns_default)) |entry| {
				if (ruleset.dns_len < max_dns_rules) {
					ruleset.dns_rules[ruleset.dns_len] = .{
						.pattern = entry.pattern,
						.action = entry.action,
					};
					ruleset.dns_len += 1;
				}
			}
			continue;
		}

		if (std.mem.startsWith(u8, trimmed, "remap ")) {
			if (parseRemapLine(trimmed)) |r| {
				if (ruleset.remap_len < max_remap_rules) {
					ruleset.remap_rules[ruleset.remap_len] = r;
					ruleset.remap_len += 1;
				}
			}
			continue;
		}

		if (parseLine(trimmed)) |rule| {
			if (ruleset.len < max_rules) {
				ruleset.rules[ruleset.len] = rule;
				ruleset.len += 1;
			}
		}
	}

	return ruleset;
}

// --- L7 (vhost) rules ---
//
// Consumed by the host-side L7 proxy (cogbox __l7proxy), NOT by the shim.
// Each rule whitelists/blacklists an SNI/Host pattern (reusing DnsPattern),
// optionally narrowed to a URL path prefix and/or marked `terminate`. The
// proxy reads these from <runtime>/l7-rules; the shim never sees them.

pub const max_l7_rules = 128;
pub const max_l7_path_len = 256;

// Loopback ports the L7 proxy listens on, and the funnel remap targets.
// PER-INSTANCE: each instance is assigned a contiguous triple derived from a
// base port (`l7PortBase` in config.json, default `l7_default_base`), so
// multiple L7-enabled instances coexist on one host without colliding on a
// shared port (which would funnel one instance's guest traffic into another
// instance's proxy -- a cross-instance policy bleed). The renderer, the proxy
// and the launch script all derive the same triple from the base:
//
//   tls  = base       (HTTPS funnel listener / remap target for :443)
//   http = base + 1    (HTTP funnel listener / remap target for :80)
//   mitm = base + 2    (proxy -> mitmproxy terminate-backend SOCKS5 hop)
//
// 18080 is intentionally avoided as a base (the test SOCKS5 stub uses it).
// The default instance keeps the canonical base; named instances allocate
// above it in steps of 3. The mitm slot is the swappable seam a future
// in-process (OpenSSL) terminator can take.
pub const l7_default_base: u16 = 18443;

pub const L7Ports = struct { tls: u16, http: u16, mitm: u16 };

/// The contiguous loopback-port triple for the instance whose L7 base is
/// `base`. Single source of truth for the renderer and the proxy (the bash
/// launcher mirrors `base + 2` for the mitmproxy invocation).
pub fn l7PortsForBase(base: u16) L7Ports {
	return .{ .tls = base, .http = base +| 1, .mitm = base +| 2 };
}

pub const L7Rule = struct {
	action: Action,
	host: DnsPattern,
	has_path: bool = false,
	path_buf: [max_l7_path_len]u8 = undefined,
	path_len: u16 = 0,
	terminate: bool = false,
	// Skip upstream TLS cert verification for this host in the terminate tier
	// (the operator's per-host equivalent of `curl -k` on the proxy->upstream
	// leg). Only meaningful for terminated hosts; implies terminate.
	insecure_upstream: bool = false,
	// Opt this host OUT of the terminate tier (back to SNI-only passthrough:
	// TLS not intercepted, cert pinning preserved). Default is terminate, so
	// this is the escape hatch for cert-pinned clients. Mutually exclusive with
	// path/terminate/insecure_upstream.
	passthrough: bool = false,

	pub fn pathSlice(self: *const L7Rule) ?[]const u8 {
		if (!self.has_path) return null;
		return self.path_buf[0..self.path_len];
	}
};

/// Result of evaluating a vhost against the L7 rules. Distinct from a bare
/// allow/deny so the proxy can compose with the L4 layer: an explicit `allow`
/// supersedes an L4 IP block, an explicit `deny` supersedes an L4 IP allow,
/// and `no_match` defers to the instance's L4 CIDR policy.
pub const L7Verdict = enum { allow, deny, no_match };

pub const L7RuleSet = struct {
	// Instance default tier. TRUE (the default) means every matched allow host
	// is MITM-terminated unless its rule says `passthrough`; FALSE (set by a
	// `mode passthrough` line) means hosts pass through unless their rule says
	// `terminate`/`path`/`insecure`. (Unlisted hosts are never intercepted --
	// they fall back to the L4 decision.)
	mode_terminate: bool = true,
	rules: [max_l7_rules]L7Rule = undefined,
	len: usize = 0,

	/// First-match allow/deny over (host[, path]); `no_match` when no rule
	/// matches (the caller then defers to the L4 CIDR policy). `path` is the
	/// request path the proxy already normalized (percent-decoded,
	/// dot-segments collapsed, query stripped). When `path` is null (HTTPS
	/// passthrough, host-only), rules that require a path simply don't match.
	///
	/// Path fail-closed: if an `allow` rule names this host but no matching
	/// rule covers the request path, the result is `deny`, not `no_match`.
	/// Otherwise a path-restricted host (`allow api.x /v1/`) accessed over
	/// cleartext HTTP would fall through to the L4 policy and bypass the path
	/// constraint whenever the IP is independently L4-allowed (the common
	/// "allow the internet at L4, restrict vhosts at L7" supersede setup).
	/// A `deny` rule whose host matches but whose path does not is NOT a
	/// fail-closed trigger -- `deny api.x /admin/` blocks only /admin/ and
	/// leaves every other path to the L4 policy.
	pub fn evaluate(self: *const L7RuleSet, host: []const u8, path: ?[]const u8) L7Verdict {
		const h = stripRootDot(host);
		var allow_host_matched = false;
		for (self.rules[0..self.len]) |r| {
			if (!matchDnsPattern(r.host, h)) continue;
			if (r.action == .allow) allow_host_matched = true;
			if (r.has_path) {
				const p = path orelse continue;
				if (!pathPrefixMatches(r.pathSlice().?, p)) continue;
			}
			return switch (r.action) {
				.allow => .allow,
				.deny => .deny,
			};
		}
		if (allow_host_matched) return .deny;
		return .no_match;
	}

	/// Should this host be served through the terminating tier (MITM)? Only
	/// matched allow hosts are candidates -- unlisted hosts are never
	/// intercepted (L4-governed). Precedence, first-match over the rules:
	///   1. explicit `passthrough` on the rule  -> NO  (cert-pinning escape)
	///   2. explicit `path`/`terminate`/`insecure` -> YES
	///   3. a built-in harness API endpoint      -> NO  (keep agents working,
	///      tokens end-to-end; an explicit per-host flag in 1/2 still wins)
	///   4. otherwise the instance default (`mode_terminate`, default TRUE)
	pub fn needsTerminate(self: *const L7RuleSet, host: []const u8) bool {
		const h = stripRootDot(host);
		var matched_allow = false;
		for (self.rules[0..self.len]) |r| {
			if (!matchDnsPattern(r.host, h)) continue;
			if (r.passthrough) return false;
			if (r.has_path or r.terminate or r.insecure_upstream) return true;
			if (r.action == .allow) matched_allow = true;
		}
		if (matched_allow and isHarnessPassthroughHost(h)) return false;
		return self.mode_terminate and matched_allow;
	}
};

/// Harness control-plane API endpoints auto-kept in passthrough under the
/// terminate-by-default tier, so the in-guest agents keep working (notably
/// rustls clients that may not honor the injected CA) and their API tokens
/// stay end-to-end (never decrypted by the host proxy). The operator must
/// still `allow` these; this only governs the tier, not allow/deny. An
/// explicit per-host `--terminate` overrides it. Provider-agnostic harnesses
/// (e.g. opencode) should `--passthrough` their configured provider host.
const harness_passthrough_hosts = [_][]const u8{
	"api.anthropic.com", // claude-code
	"api.openai.com", // codex
	"chatgpt.com", // codex (ChatGPT auth/backend)
	"auth.openai.com", // codex auth
};

pub fn isHarnessPassthroughHost(host: []const u8) bool {
	const h = stripRootDot(host);
	for (harness_passthrough_hosts) |hh| {
		if (std.ascii.eqlIgnoreCase(h, hh)) return true;
	}
	return false;
}

fn stripRootDot(host: []const u8) []const u8 {
	if (host.len > 0 and host[host.len - 1] == '.') return host[0 .. host.len - 1];
	return host;
}

/// Boundary-aware left-anchored prefix match. `rule_path` matches `req_path`
/// iff they are equal, or `req_path` extends `rule_path` at a `/` boundary.
/// e.g. `/api` matches `/api`, `/api/`, `/api/v1` but NOT `/apifoo`.
/// Both inputs are expected pre-normalized.
pub fn pathPrefixMatches(rule_path: []const u8, req_path: []const u8) bool {
	if (req_path.len < rule_path.len) return false;
	if (!std.mem.startsWith(u8, req_path, rule_path)) return false;
	if (req_path.len == rule_path.len) return true;
	if (rule_path.len > 0 and rule_path[rule_path.len - 1] == '/') return true;
	return req_path[rule_path.len] == '/';
}

pub const L7Line = union(enum) {
	rule: L7Rule,
	mode_terminate: bool,
	none, // blank / comment / malformed
};

/// Parse a single `l7-rules` line:
///   mode passthrough|terminate
///   allow|deny  <host-pattern>  [<path>]  [terminate|passthrough]  [insecure]
/// Tokens are whitespace-separated. A token starting with `/` is the path;
/// `terminate` forces the terminate tier, `passthrough` forces SNI-only
/// passthrough, `insecure` skips upstream cert verification (terminate tier
/// only). Order of the trailing tokens is not significant. Malformed lines
/// return `.none` (dropped, fail-closed).
pub fn parseL7Line(line: []const u8) L7Line {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return .none;

	var it = std.mem.tokenizeAny(u8, trimmed, " \t");
	const head = it.next() orelse return .none;

	if (std.mem.eql(u8, head, "mode")) {
		const v = it.next() orelse return .none;
		if (std.mem.eql(u8, v, "terminate")) return .{ .mode_terminate = true };
		if (std.mem.eql(u8, v, "passthrough")) return .{ .mode_terminate = false };
		return .none;
	}

	var action: Action = undefined;
	if (std.mem.eql(u8, head, "allow")) {
		action = .allow;
	} else if (std.mem.eql(u8, head, "deny")) {
		action = .deny;
	} else {
		return .none;
	}

	const host_tok = it.next() orelse return .none;
	const pat = parseDnsPattern(host_tok) orelse return .none;

	var rule: L7Rule = .{ .action = action, .host = pat };
	while (it.next()) |tok| {
		if (std.mem.eql(u8, tok, "terminate")) {
			rule.terminate = true;
		} else if (std.mem.eql(u8, tok, "passthrough")) {
			rule.passthrough = true;
		} else if (std.mem.eql(u8, tok, "insecure")) {
			rule.insecure_upstream = true;
		} else if (tok.len > 0 and tok[0] == '/') {
			if (rule.has_path) return .none; // duplicate path
			if (tok.len > max_l7_path_len) return .none;
			@memcpy(rule.path_buf[0..tok.len], tok);
			rule.path_len = @intCast(tok.len);
			rule.has_path = true;
		} else {
			return .none; // unknown token -> reject the whole line
		}
	}
	return .{ .rule = rule };
}

/// Parse a multi-line `l7-rules` document into `out` (passed by pointer to
/// avoid copying the large fixed-size table).
pub fn parseL7Rules(content: []const u8, out: *L7RuleSet) void {
	out.* = .{};
	var lines = std.mem.splitScalar(u8, content, '\n');
	while (lines.next()) |line| {
		switch (parseL7Line(line)) {
			.none => {},
			.mode_terminate => |t| out.mode_terminate = t,
			.rule => |r| {
				if (out.len < max_l7_rules) {
					out.rules[out.len] = r;
					out.len += 1;
				}
			},
		}
	}
}

// --- Tests ---

test "parseIpv4 valid" {
	const result = parseIpv4("192.168.1.1").?;
	try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, result);
}

test "parseIpv4 zeros" {
	const result = parseIpv4("0.0.0.0").?;
	try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, result);
}

test "parseIpv4 invalid" {
	try std.testing.expect(parseIpv4("256.0.0.0") == null);
	try std.testing.expect(parseIpv4("1.2.3") == null);
	try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
	try std.testing.expect(parseIpv4("abc") == null);
	try std.testing.expect(parseIpv4("") == null);
}

test "parseIpv6 :: forms" {
	try std.testing.expectEqual([_]u8{0} ** 16, parseIpv6("::").?);
	const lo = parseIpv6("::1").?;
	try std.testing.expectEqual(@as(u8, 1), lo[15]);
	const full = parseIpv6("2001:db8::1").?;
	try std.testing.expectEqual([_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, full);
	try std.testing.expect(parseIpv6("2001:::1") == null);
	try std.testing.expect(parseIpv6("xyz") == null);
	try std.testing.expect(parseIpv6("::ffff:1.2.3.4") == null); // embedded v4 not supported
}

test "parseLine accepts port-less IPv6 CIDR" {
	const r = parseLine("deny tcp ::/0").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u8, 0), r.prefix_len);
	try std.testing.expectEqual(@as(u16, 0), r.port);
	try std.testing.expectEqual([_]u8{0} ** 16, r.network.ipv6);
}

test "evaluate honors v6 deny-all but keeps DNS" {
	const rs = parseRules(
		\\deny tcp ::/0
		\\deny udp ::/0
	);
	const v6 = IpAddr{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, v6, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, v6, 443));
	// DNS (port 53) stays implicitly allowed
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, v6, 53));
}

test "parseLine allow" {
	const rule = parseLine("allow 10.0.0.0/8").?;
	try std.testing.expectEqual(Action.allow, rule.action);
	try std.testing.expectEqual([4]u8{ 10, 0, 0, 0 }, rule.network.ipv4);
	try std.testing.expectEqual(@as(u8, 8), rule.prefix_len);
}

test "parseLine deny" {
	const rule = parseLine("deny 0.0.0.0/0").?;
	try std.testing.expectEqual(Action.deny, rule.action);
	try std.testing.expectEqual(@as(u8, 0), rule.prefix_len);
}

test "parseLine skip empty and comments" {
	try std.testing.expect(parseLine("") == null);
	try std.testing.expect(parseLine("# comment") == null);
	try std.testing.expect(parseLine("   ") == null);
}

test "parseLine invalid" {
	try std.testing.expect(parseLine("allow 10.0.0.0") == null);
	try std.testing.expect(parseLine("allow 10.0.0.0/33") == null);
	try std.testing.expect(parseLine("block 10.0.0.0/8") == null);
}

test "ipv4 CIDR /8" {
	try std.testing.expect(ipv4Matches(.{ 10, 0, 0, 0 }, .{ 10, 1, 2, 3 }, 8));
	try std.testing.expect(!ipv4Matches(.{ 10, 0, 0, 0 }, .{ 11, 0, 0, 0 }, 8));
}

test "ipv4 CIDR /32 exact" {
	try std.testing.expect(ipv4Matches(.{ 1, 2, 3, 4 }, .{ 1, 2, 3, 4 }, 32));
	try std.testing.expect(!ipv4Matches(.{ 1, 2, 3, 4 }, .{ 1, 2, 3, 5 }, 32));
}

test "ipv4 CIDR /0 matches all" {
	try std.testing.expect(ipv4Matches(.{ 0, 0, 0, 0 }, .{ 255, 255, 255, 255 }, 0));
}

test "ipv4 CIDR /24" {
	try std.testing.expect(ipv4Matches(.{ 192, 168, 1, 0 }, .{ 192, 168, 1, 254 }, 24));
	try std.testing.expect(!ipv4Matches(.{ 192, 168, 1, 0 }, .{ 192, 168, 2, 1 }, 24));
}

test "ipv6 CIDR matching" {
	const net = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	const ip_match = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	const ip_no = [16]u8{ 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	try std.testing.expect(ipv6Matches(net, ip_match, 32));
	try std.testing.expect(!ipv6Matches(net, ip_no, 32));
	try std.testing.expect(ipv6Matches(net, ip_no, 0));
}

test "isIpv4Mapped" {
	const mapped = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1 };
	const not_mapped = [16]u8{ 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

	try std.testing.expect(isIpv4Mapped(mapped));
	try std.testing.expect(!isIpv4Mapped(not_mapped));
}

test "RuleSet evaluate loopback denied" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 80));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv6 = ipv6_loopback }, 80));
}

test "RuleSet evaluate loopback DNS allowed" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv6 = ipv6_loopback }, 53));
}

test "RuleSet evaluate DNS" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 53));
}

test "RuleSet evaluate default deny" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "RuleSet evaluate user rules in order" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\deny 192.168.0.0/16
		\\allow 0.0.0.0/0
	);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 10, 1, 2, 3 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 192, 168, 1, 1 } }, 443));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "RuleSet evaluate IPv4-mapped IPv6" {
	const rs = parseRules("deny 10.0.0.0/8");
	const mapped = IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, mapped, 443));
}

test "parseRules multi-line with comments" {
	const content =
		\\# Allow internal
		\\allow 10.0.0.0/8
		\\
		\\deny 0.0.0.0/0
	;
	const rs = parseRules(content);
	try std.testing.expectEqual(@as(usize, 2), rs.len);
	try std.testing.expectEqual(Action.allow, rs.rules[0].action);
	try std.testing.expectEqual(Action.deny, rs.rules[1].action);
}

// --- DNS ---

test "parseDnsPattern exact" {
	const p = parseDnsPattern("api.anthropic.com").?;
	try std.testing.expectEqual(DnsPatternKind.exact, p.kind);
	try std.testing.expectEqualStrings("api.anthropic.com", p.slice());
}

test "parseDnsPattern left wildcard strips star-dot" {
	const p = parseDnsPattern("*.githubusercontent.com").?;
	try std.testing.expectEqual(DnsPatternKind.left_wildcard, p.kind);
	try std.testing.expectEqualStrings("githubusercontent.com", p.slice());
}

test "parseDnsPattern bare star" {
	const p = parseDnsPattern("*").?;
	try std.testing.expectEqual(DnsPatternKind.any, p.kind);
}

test "parseDnsPattern rejects right-anchored wildcard" {
	try std.testing.expect(parseDnsPattern("api.*") == null);
	try std.testing.expect(parseDnsPattern("foo.*.com") == null);
	try std.testing.expect(parseDnsPattern("*.foo.*") == null);
}

test "parseDnsPattern rejects malformed names" {
	try std.testing.expect(parseDnsPattern("") == null);
	try std.testing.expect(parseDnsPattern(".") == null);
	try std.testing.expect(parseDnsPattern(".com") == null);
	try std.testing.expect(parseDnsPattern("com.") == null);
	try std.testing.expect(parseDnsPattern("foo..bar") == null);
	try std.testing.expect(parseDnsPattern("foo bar") == null);
	try std.testing.expect(parseDnsPattern("-foo.com") == null);
	try std.testing.expect(parseDnsPattern("*.") == null);
}

test "matchDnsPattern exact case-insensitive" {
	const p = parseDnsPattern("api.anthropic.com").?;
	try std.testing.expect(matchDnsPattern(p, "api.anthropic.com"));
	try std.testing.expect(matchDnsPattern(p, "API.Anthropic.COM"));
	try std.testing.expect(!matchDnsPattern(p, "x.api.anthropic.com"));
	try std.testing.expect(!matchDnsPattern(p, "anthropic.com"));
}

test "matchDnsPattern left wildcard requires >=1 subdomain label" {
	const p = parseDnsPattern("*.example.com").?;
	try std.testing.expect(matchDnsPattern(p, "a.example.com"));
	try std.testing.expect(matchDnsPattern(p, "a.b.example.com"));
	try std.testing.expect(matchDnsPattern(p, "A.Example.COM"));
	try std.testing.expect(!matchDnsPattern(p, "example.com"));
	try std.testing.expect(!matchDnsPattern(p, "evilexample.com"));
	try std.testing.expect(!matchDnsPattern(p, "com"));
}

test "matchDnsPattern bare star matches everything" {
	const p = parseDnsPattern("*").?;
	try std.testing.expect(matchDnsPattern(p, "x"));
	try std.testing.expect(matchDnsPattern(p, "anything.example.com"));
}

test "RuleSet evaluateDns default allow" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("anywhere.example"));
}

test "RuleSet evaluateDns first match wins, default applies" {
	const rs = parseRules(
		\\dns default deny
		\\dns allow api.anthropic.com
		\\dns allow *.githubusercontent.com
		\\dns deny telemetry.example.com
	);
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("api.anthropic.com"));
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("raw.githubusercontent.com"));
	try std.testing.expectEqual(Action.deny, rs.evaluateDns("telemetry.example.com"));
	try std.testing.expectEqual(Action.deny, rs.evaluateDns("unspecified.example"));
}

test "RuleSet evaluateDns strips trailing root dot" {
	const rs = parseRules(
		\\dns default deny
		\\dns allow api.anthropic.com
	);
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("api.anthropic.com."));
}

test "parseRules mixed CIDR + DNS rules go to separate tables" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\dns default deny
		\\dns allow api.anthropic.com
		\\deny 0.0.0.0/0
	);
	try std.testing.expectEqual(@as(usize, 2), rs.len);
	try std.testing.expectEqual(@as(usize, 1), rs.dns_len);
	try std.testing.expectEqual(Action.deny, rs.dns_default);
	try std.testing.expectEqual(Action.allow, rs.dns_rules[0].action);
	try std.testing.expectEqualStrings("api.anthropic.com", rs.dns_rules[0].pattern.slice());
}

// --- proto/port qualifiers + remap ---

test "parseLine with tcp proto qualifier" {
	const r = parseLine("allow tcp 10.0.0.0/8").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u16, 0), r.port);
}

test "parseLine with port qualifier" {
	const r = parseLine("deny 0.0.0.0/0:25").?;
	try std.testing.expectEqual(Proto.any, r.proto);
	try std.testing.expectEqual(@as(u16, 25), r.port);
}

test "parseLine with proto + port" {
	const r = parseLine("allow tcp 10.0.0.0/8:443").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u16, 443), r.port);
}

test "parseLine backward compat: no qualifiers" {
	const r = parseLine("allow 10.0.0.0/8").?;
	try std.testing.expectEqual(Proto.any, r.proto);
	try std.testing.expectEqual(@as(u16, 0), r.port);
}

test "evaluate honors proto qualifier" {
	const rs = parseRules("allow tcp 8.8.8.8/32");
	try std.testing.expectEqual(Action.allow, rs.evaluate(.tcp, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "evaluate honors port qualifier" {
	const rs = parseRules("deny 0.0.0.0/0:25");
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 25));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 26)); // default-deny on no match
}

test "evaluate proto+port qualifier matches narrowly" {
	const rs = parseRules(
		\\allow tcp 0.0.0.0/0:443
		\\deny 0.0.0.0/0
	);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 80));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "parseRemapLine basic" {
	const r = parseRemapLine("remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u8, 0), r.prefix_len);
	try std.testing.expectEqual(@as(u16, 443), r.port);
	try std.testing.expectEqual(Proto.tcp, r.target.proto);
	try std.testing.expectEqual(@as(u16, 18080), r.target.port);
	try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, r.target.addr.ipv4);
}

test "parseRemapLine narrow source CIDR" {
	const r = parseRemapLine("remap tcp 1.2.3.0/24:80 -> tcp 127.0.0.1:18081").?;
	try std.testing.expectEqual([4]u8{ 1, 2, 3, 0 }, r.network.ipv4);
	try std.testing.expectEqual(@as(u8, 24), r.prefix_len);
}

test "parseRemapLine rejects missing proto, missing port, udp, multi-host target" {
	try std.testing.expect(parseRemapLine("remap 0.0.0.0/0:443 -> tcp 127.0.0.1:8080") == null);
	try std.testing.expect(parseRemapLine("remap tcp 0.0.0.0/0 -> tcp 127.0.0.1:8080") == null);
	try std.testing.expect(parseRemapLine("remap udp 0.0.0.0/0:53 -> udp 127.0.0.1:1053") == null);
	try std.testing.expect(parseRemapLine("remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.0/24:8080") == null);
	try std.testing.expect(parseRemapLine("remap tcp 0.0.0.0/0:443") == null);
}

test "evaluateRemap returns target on match, null otherwise" {
	const rs = parseRules("remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080");
	const tgt = rs.evaluateRemap(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443).?;
	try std.testing.expectEqual(@as(u16, 18080), tgt.port);
	try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, tgt.addr.ipv4);
	try std.testing.expect(rs.evaluateRemap(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 80) == null);
	try std.testing.expect(rs.evaluateRemap(.udp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443) == null);
}

test "parseRules mixes CIDR + remap + DNS into three tables" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080
		\\dns default deny
		\\dns allow api.anthropic.com
	);
	try std.testing.expectEqual(@as(usize, 1), rs.len);
	try std.testing.expectEqual(@as(usize, 1), rs.remap_len);
	try std.testing.expectEqual(@as(usize, 1), rs.dns_len);
}

// --- isLoopback / isHardBlocked ---

test "isLoopback v4/v6/mapped" {
	try std.testing.expect(isLoopback(.{ .ipv4 = .{ 127, 0, 0, 1 } }));
	try std.testing.expect(isLoopback(.{ .ipv4 = .{ 127, 9, 9, 9 } }));
	try std.testing.expect(!isLoopback(.{ .ipv4 = .{ 8, 8, 8, 8 } }));
	try std.testing.expect(isLoopback(.{ .ipv6 = ipv6_loopback }));
	const mapped_lo = IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 } };
	try std.testing.expect(isLoopback(mapped_lo));
}

test "isHardBlocked: loopback/this-net/link-local only; private ranges deferred to CIDR" {
	// Hard-blocked (non-overridable): loopback, this-network, link-local/metadata.
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 127, 0, 0, 1 } }));
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 0, 0, 0, 0 } }));
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 169, 254, 169, 254 } }));
	// v4-mapped metadata
	try std.testing.expect(isHardBlocked(.{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 } }));
	// v6 loopback / unspecified / link-local
	try std.testing.expect(isHardBlocked(.{ .ipv6 = ipv6_loopback }));
	try std.testing.expect(isHardBlocked(.{ .ipv6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }));

	// NOT hard-blocked: RFC1918 / CGNAT / ULA -- governed by the instance CIDR
	// policy (default-denied by seeded rules, reachable via an explicit allow).
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 10, 1, 2, 3 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 172, 16, 5, 5 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 192, 168, 1, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 100, 64, 0, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }));

	// Public addresses always pass.
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 1, 1, 1, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 93, 184, 216, 34 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }));
}

// --- L7 rules ---

test "pathPrefixMatches boundary-aware" {
	try std.testing.expect(pathPrefixMatches("/api", "/api"));
	try std.testing.expect(pathPrefixMatches("/api", "/api/"));
	try std.testing.expect(pathPrefixMatches("/api", "/api/v1"));
	try std.testing.expect(!pathPrefixMatches("/api", "/apifoo"));
	try std.testing.expect(!pathPrefixMatches("/api", "/ap"));
	try std.testing.expect(pathPrefixMatches("/v1/", "/v1/x"));
	try std.testing.expect(pathPrefixMatches("/v1/", "/v1/"));
	try std.testing.expect(!pathPrefixMatches("/v1/", "/v1"));
}

test "L7 evaluate first-match: allow / deny / no_match" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode passthrough
		\\allow vhost-a.test
		\\allow *.cdn.test
		\\deny telemetry.test
	, &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("vhost-a.test", null));
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("x.cdn.test", null));
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("telemetry.test", null));
	// a sibling not in any rule is NO_MATCH -> the proxy defers to L4
	// (so allowing vhost-a does not by itself grant vhost-b; vhost-b is only
	// reachable if its IP is L4-allowed)
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("vhost-b.test", null));
	// trailing root dot is stripped
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("vhost-a.test.", null));
	try std.testing.expect(!rs.mode_terminate);
}

test "L7 evaluate no_match falls through (no implicit deny)" {
	var rs: L7RuleSet = undefined;
	parseL7Rules("allow only.test", &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("only.test", null));
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("other.test", null));
}

test "L7 explicit deny * supersedes L4 (catch-all)" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\allow a.test
		\\deny *
	, &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("a.test", null));
	// deny * makes everything else an explicit deny, not no_match
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("b.test", null));
}

test "L7 path rules + needsTerminate" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode passthrough
		\\allow api.example.com /v1/ terminate
		\\allow plain.test
		\\deny *
	, &rs);
	// host with a path rule needs the terminating tier; a plain allow doesn't
	try std.testing.expect(rs.needsTerminate("api.example.com"));
	try std.testing.expect(!rs.needsTerminate("plain.test"));
	// an unlisted host is never terminated (passthrough / L4)
	try std.testing.expect(!rs.needsTerminate("unlisted.test"));
	// path enforcement: only /v1/* allowed for api.example.com
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("api.example.com", "/v1/x"));
	// /v2/x doesn't match the path rule, but `deny *` catches it
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("api.example.com", "/v2/x"));
}

test "L7 path fail-closed: allow-host + uncovered path is deny, not no_match" {
	var rs: L7RuleSet = undefined;
	// No catch-all `deny *` -- the supersede setup relies on no_match
	// deferring to L4, so a path miss must NOT silently defer to an
	// L4-allowed IP. An allow rule named the host, so an uncovered path
	// fails closed.
	parseL7Rules(
		\\allow api.example.com /v1/ terminate
		\\allow plain.test
	, &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("api.example.com", "/v1/sub"));
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("api.example.com", "/v2/x"));
	// host with no path constraint is still a clean allow
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("plain.test", "/anything"));
	// a wholly unlisted host stays no_match (defers to L4)
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("other.test", "/v1/"));
}

test "L7 deny-path rule does not fail closed for other paths" {
	var rs: L7RuleSet = undefined;
	// `deny api.example.com /admin/` blocks only /admin/; other paths
	// defer to L4 (no_match), because no allow rule names the host.
	parseL7Rules(
		\\deny api.example.com /admin/ terminate
	, &rs);
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("api.example.com", "/admin/panel"));
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("api.example.com", "/public/"));
}

test "l7PortsForBase: contiguous triple, no cross-instance overlap" {
	const a = l7PortsForBase(l7_default_base); // default instance
	try std.testing.expectEqual(@as(u16, 18443), a.tls);
	try std.testing.expectEqual(@as(u16, 18444), a.http);
	try std.testing.expectEqual(@as(u16, 18445), a.mitm);
	// next instance's base is +3, so its triple is disjoint from the default's
	const b = l7PortsForBase(l7_default_base + 3);
	try std.testing.expectEqual(@as(u16, 18446), b.tls);
	try std.testing.expectEqual(@as(u16, 18448), b.mitm);
	try std.testing.expect(b.tls > a.mitm); // no overlap
}

test "L7 mode terminate floor applies to matched allow hosts only" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode terminate
		\\allow a.test
	, &rs);
	try std.testing.expect(rs.mode_terminate);
	try std.testing.expect(rs.needsTerminate("a.test"));
	// unlisted host is NOT terminated even under the mode floor
	try std.testing.expect(!rs.needsTerminate("unlisted.test"));
}

test "L7 terminate-by-default + passthrough opt-out + harness safety" {
	var rs: L7RuleSet = undefined;
	// No mode line -> the instance default tier is TERMINATE.
	parseL7Rules(
		\\allow plain.test
		\\allow pinned.test passthrough
		\\allow api.anthropic.com
		\\allow api.openai.com terminate
	, &rs);
	try std.testing.expect(rs.mode_terminate); // default tier is terminate
	// a bare allow host is terminated by default
	try std.testing.expect(rs.needsTerminate("plain.test"));
	// --passthrough opts a host out (cert-pinning escape)
	try std.testing.expect(!rs.needsTerminate("pinned.test"));
	// a harness API endpoint stays passthrough automatically...
	try std.testing.expect(!rs.needsTerminate("api.anthropic.com"));
	try std.testing.expect(isHarnessPassthroughHost("API.Anthropic.Com")); // case-insensitive
	// ...unless explicitly --terminate'd
	try std.testing.expect(rs.needsTerminate("api.openai.com"));
	// unlisted host is never terminated
	try std.testing.expect(!rs.needsTerminate("unlisted.test"));
}

test "L7 mode passthrough flips the default back" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode passthrough
		\\allow plain.test
		\\allow api.test /v1/ terminate
	, &rs);
	try std.testing.expect(!rs.mode_terminate);
	try std.testing.expect(!rs.needsTerminate("plain.test")); // passthrough default
	try std.testing.expect(rs.needsTerminate("api.test")); // explicit terminate still wins
}

test "parseL7Line rejects malformed" {
	try std.testing.expect(parseL7Line("") == .none);
	try std.testing.expect(parseL7Line("# comment") == .none);
	try std.testing.expect(parseL7Line("allow") == .none); // no host
	try std.testing.expect(parseL7Line("allow *.foo.*") == .none); // bad pattern
	try std.testing.expect(parseL7Line("allow a.test bogustoken") == .none);
	try std.testing.expect(parseL7Line("mode sideways") == .none);
	const r = parseL7Line("allow a.test /p/ terminate");
	try std.testing.expect(r == .rule);
	try std.testing.expect(r.rule.terminate);
	try std.testing.expectEqualStrings("/p/", r.rule.pathSlice().?);
}

test "parseL7Line insecure token + needsTerminate" {
	// `insecure` parses, is order-independent, and on its own implies the
	// terminate tier (it only governs the proxy<->upstream TLS leg).
	const r = parseL7Line("allow internal.svc insecure");
	try std.testing.expect(r == .rule);
	try std.testing.expect(r.rule.insecure_upstream);
	try std.testing.expect(!r.rule.has_path);

	const r2 = parseL7Line("allow internal.svc /api/ insecure terminate");
	try std.testing.expect(r2 == .rule);
	try std.testing.expect(r2.rule.insecure_upstream);
	try std.testing.expect(r2.rule.terminate);
	try std.testing.expectEqualStrings("/api/", r2.rule.pathSlice().?);

	// a host whose only flag is `insecure` (no path, no explicit terminate)
	// is still routed through the terminating tier.
	var rs: L7RuleSet = undefined;
	parseL7Rules("allow internal.svc insecure", &rs);
	try std.testing.expect(rs.needsTerminate("internal.svc"));
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("internal.svc", null));
}
