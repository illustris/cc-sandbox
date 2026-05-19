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
		switch (addr) {
			.ipv4 => |ip| {
				if (ip[0] == 127) return .deny;
			},
			.ipv6 => |ip| {
				if (std.mem.eql(u8, &ip, &ipv6_loopback)) return .deny;
				if (isIpv4Mapped(ip) and ip[12] == 127) return .deny;
			},
		}

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
fn isValidHostName(s: []const u8) bool {
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

	// Split off `:port` if present. v1 supports IPv4 only here, so we
	// can safely treat any single colon as the port separator.
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
