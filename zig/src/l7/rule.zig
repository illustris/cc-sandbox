// Rule operations on the `.network.l7.rules` array. Each rule object has
// exactly one of `allow` or `deny` keyed to an SNI/Host pattern (the same
// grammar as DNS patterns: exact / *.suffix / *), and may optionally carry a
// `comment`. Path/terminate fields are reserved for the Phase 2 terminate
// tier and are not written by the Phase 1 CLI.

const std = @import("std");
const filter = @import("filter");

pub const Action = enum { allow, deny };

pub const Mutation = error{
	IndexOutOfRange,
	InvalidHost,
	InvalidLine,
	OutOfMemory,
};

pub const Pair = struct {
	action: Action,
	host: []const u8,
};

/// A host pattern is valid iff it parses as a DNS pattern (exact, *.suffix,
/// or bare *). The shim's matcher and the proxy both reuse parseDnsPattern,
/// so the CLI cannot admit a pattern they would reject.
pub fn validateHost(host: []const u8) bool {
	return filter.parseDnsPattern(host) != null;
}

pub fn newRuleObject(allocator: std.mem.Allocator, action: Action, host: []const u8) !std.json.Value {
	var obj: std.json.ObjectMap = .empty;
	const action_key = try allocator.dupe(u8, switch (action) {
		.allow => "allow",
		.deny => "deny",
	});
	const host_dup = try allocator.dupe(u8, host);
	try obj.put(allocator, action_key, .{ .string = host_dup });
	return .{ .object = obj };
}

pub fn append(allocator: std.mem.Allocator, arr: *std.json.Array, action: Action, host: []const u8) !usize {
	if (!validateHost(host)) return error.InvalidHost;
	const obj = try newRuleObject(allocator, action, host);
	try arr.append(obj);
	return arr.items.len;
}

pub fn insertAt(allocator: std.mem.Allocator, arr: *std.json.Array, pos: usize, action: Action, host: []const u8) !void {
	if (pos < 1 or pos > arr.items.len + 1) return error.IndexOutOfRange;
	if (!validateHost(host)) return error.InvalidHost;
	const obj = try newRuleObject(allocator, action, host);
	try arr.insert(pos - 1, obj);
}

pub fn delete(arr: *std.json.Array, index: usize) !void {
	if (index < 1 or index > arr.items.len) return error.IndexOutOfRange;
	_ = arr.orderedRemove(index - 1);
}

pub fn replaceAll(allocator: std.mem.Allocator, arr: *std.json.Array, items: []const Pair) !void {
	arr.clearRetainingCapacity();
	for (items) |p| {
		if (!validateHost(p.host)) return error.InvalidHost;
		const obj = try newRuleObject(allocator, p.action, p.host);
		try arr.append(obj);
	}
}

/// Parse a single `set` line: `allow|deny HOST` (blank / `#` lines skipped).
pub fn parseSetLine(line: []const u8) !?Pair {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;
	if (std.mem.startsWith(u8, trimmed, "allow ")) {
		const host = std.mem.trim(u8, trimmed[6..], " \t");
		if (!validateHost(host)) return error.InvalidLine;
		return .{ .action = .allow, .host = host };
	}
	if (std.mem.startsWith(u8, trimmed, "deny ")) {
		const host = std.mem.trim(u8, trimmed[5..], " \t");
		if (!validateHost(host)) return error.InvalidLine;
		return .{ .action = .deny, .host = host };
	}
	return error.InvalidLine;
}

/// Read action+host from a rule object, ignoring path/terminate for the
/// Phase 1 `list` view (it returns the host string only).
pub fn ruleAction(obj: std.json.ObjectMap) ?Pair {
	if (obj.get("allow")) |v| {
		if (v == .string) return .{ .action = .allow, .host = v.string };
	}
	if (obj.get("deny")) |v| {
		if (v == .string) return .{ .action = .deny, .host = v.string };
	}
	return null;
}

pub fn ruleComment(obj: std.json.ObjectMap) ?[]const u8 {
	if (obj.get("comment")) |v| {
		if (v == .string) return v.string;
	}
	return null;
}
