const std = @import("std");

pub const Action = enum {
	allow,
	deny,
};

pub const IpAddr = union(enum) {
	ipv4: [4]u8,
	ipv6: [16]u8,
};

pub const Rule = struct {
	network: IpAddr,
	prefix_len: u8,
	action: Action,
};

pub const max_rules = 256;

pub const RuleSet = struct {
	rules: [max_rules]Rule = undefined,
	len: usize = 0,

	/// Evaluate a destination address and port against the ruleset.
	pub fn evaluate(self: *const RuleSet, addr: IpAddr, port: u16) Action {
		// Implicit: allow DNS (port 53) -- checked first so DNS to
		// loopback resolvers (e.g. 127.0.0.53 systemd-resolved) works.
		if (port == 53) return .allow;

		// Implicit: deny loopback -- passt maps its gateway and the
		// host's IP to 127.0.0.1, so allowing loopback would expose
		// all host services to the sandbox.
		switch (addr) {
			.ipv4 => |ip| {
				if (ip[0] == 127) return .deny;
			},
			.ipv6 => |ip| {
				if (std.mem.eql(u8, &ip, &ipv6_loopback)) return .deny;
				if (isIpv4Mapped(ip) and ip[12] == 127) return .deny;
			},
		}

		// Normalize IPv4-mapped IPv6 to IPv4 for rule matching
		const check_addr: IpAddr = switch (addr) {
			.ipv6 => |ip| if (isIpv4Mapped(ip))
				.{ .ipv4 = .{ ip[12], ip[13], ip[14], ip[15] } }
			else
				addr,
			.ipv4 => addr,
		};

		// Walk user rules in order, first match wins
		for (self.rules[0..self.len]) |rule| {
			if (cidrMatches(rule, check_addr)) {
				return rule.action;
			}
		}

		// Default: deny
		return .deny;
	}
};

const ipv6_loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const ipv4_mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

pub fn isIpv4Mapped(ip: [16]u8) bool {
	return std.mem.eql(u8, ip[0..12], &ipv4_mapped_prefix);
}

fn cidrMatches(rule: Rule, addr: IpAddr) bool {
	return switch (rule.network) {
		.ipv4 => |net| switch (addr) {
			.ipv4 => |ip| ipv4Matches(net, ip, rule.prefix_len),
			.ipv6 => false,
		},
		.ipv6 => |net| switch (addr) {
			.ipv6 => |ip| ipv6Matches(net, ip, rule.prefix_len),
			.ipv4 => false,
		},
	};
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

/// Parse a single rule line like "allow 10.0.0.0/8" or "deny 0.0.0.0/0".
/// Returns null for empty lines, comments, or malformed input.
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

	const cidr = std.mem.trim(u8, rest, " \t");
	const slash_pos = std.mem.indexOfScalar(u8, cidr, '/') orelse return null;
	const ip_str = cidr[0..slash_pos];
	const prefix_str = cidr[slash_pos + 1 ..];
	const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return null;

	if (parseIpv4(ip_str)) |ipv4| {
		if (prefix_len > 32) return null;
		return .{
			.network = .{ .ipv4 = ipv4 },
			.prefix_len = prefix_len,
			.action = action,
		};
	}

	// IPv6 rule parsing not yet implemented
	return null;
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
		if (parseLine(line)) |rule| {
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
	try std.testing.expectEqual(Action.deny, rs.evaluate(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 80));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.{ .ipv6 = ipv6_loopback }, 80));
}

test "RuleSet evaluate loopback DNS allowed" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluate(.{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.{ .ipv6 = ipv6_loopback }, 53));
}

test "RuleSet evaluate DNS" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluate(.{ .ipv4 = .{ 8, 8, 8, 8 } }, 53));
}

test "RuleSet evaluate default deny" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.deny, rs.evaluate(.{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "RuleSet evaluate user rules in order" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\deny 192.168.0.0/16
		\\allow 0.0.0.0/0
	);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.{ .ipv4 = .{ 10, 1, 2, 3 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.{ .ipv4 = .{ 192, 168, 1, 1 } }, 443));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "RuleSet evaluate IPv4-mapped IPv6" {
	const rs = parseRules("deny 10.0.0.0/8");
	const mapped = IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(mapped, 443));
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
