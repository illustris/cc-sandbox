// Rule operations on a std.json.Array of rule objects. Each rule object has
// exactly one of `allow` or `deny` keyed to a CIDR string, and may optionally
// carry a `comment` field that is preserved verbatim.

const std = @import("std");
const filter = @import("filter");

pub const Action = enum { allow, deny };

pub const Mutation = error{
	IndexOutOfRange,
	InvalidCidr,
	InvalidLine,
	OutOfMemory,
};

/// Build a fresh rule object {"allow|deny": "CIDR"} owning its strings.
/// Strings are duplicated using `allocator`, which must outlive the value
/// (typically the json.Parsed's arena allocator).
pub fn newRuleObject(allocator: std.mem.Allocator, action: Action, cidr: []const u8) !std.json.Value {
	var obj: std.json.ObjectMap = .empty;
	const action_key = try allocator.dupe(u8, switch (action) {
		.allow => "allow",
		.deny => "deny",
	});
	const cidr_dup = try allocator.dupe(u8, cidr);
	try obj.put(allocator, action_key, .{ .string = cidr_dup });
	return .{ .object = obj };
}

/// Validate that "action CIDR" parses according to the runtime filter.
pub fn validateActionCidr(action: Action, cidr: []const u8, line_buf: []u8) bool {
	const action_str = switch (action) {
		.allow => "allow",
		.deny => "deny",
	};
	const line = std.fmt.bufPrint(line_buf, "{s} {s}", .{ action_str, cidr }) catch return false;
	return filter.parseLine(line) != null;
}

/// Append a rule. Returns the new index (1-based).
pub fn append(allocator: std.mem.Allocator, arr: *std.json.Array, action: Action, cidr: []const u8) !usize {
	var line_buf: [128]u8 = undefined;
	if (!validateActionCidr(action, cidr, &line_buf)) return error.InvalidCidr;
	const obj = try newRuleObject(allocator, action, cidr);
	try arr.append(obj);
	return arr.items.len;
}

/// Insert a rule at `pos` (1-based). pos == len+1 is equivalent to append.
pub fn insertAt(allocator: std.mem.Allocator, arr: *std.json.Array, pos: usize, action: Action, cidr: []const u8) !void {
	if (pos < 1 or pos > arr.items.len + 1) return error.IndexOutOfRange;
	var line_buf: [128]u8 = undefined;
	if (!validateActionCidr(action, cidr, &line_buf)) return error.InvalidCidr;
	const obj = try newRuleObject(allocator, action, cidr);
	try arr.insert(pos - 1, obj);
}

/// Delete a rule by 1-based index.
pub fn delete(arr: *std.json.Array, index: usize) !void {
	if (index < 1 or index > arr.items.len) return error.IndexOutOfRange;
	_ = arr.orderedRemove(index - 1);
}

/// Replace the entire array contents from a list of (action, cidr) pairs.
/// Existing elements are dropped; new ones do not carry comments.
pub fn replaceAll(allocator: std.mem.Allocator, arr: *std.json.Array, items: []const Pair) !void {
	arr.clearRetainingCapacity();
	for (items) |p| {
		var line_buf: [128]u8 = undefined;
		if (!validateActionCidr(p.action, p.cidr, &line_buf)) return error.InvalidCidr;
		const obj = try newRuleObject(allocator, p.action, p.cidr);
		try arr.append(obj);
	}
}

pub const Pair = struct {
	action: Action,
	cidr: []const u8,
};

/// Parse a single line of `set` input (same syntax as the runtime rules
/// file: "allow|deny CIDR", with `#` comments and blank lines skipped).
/// Returns null for skipped lines, error.InvalidLine for malformed.
pub fn parseSetLine(line: []const u8) !?Pair {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;
	if (filter.parseLine(trimmed) == null) return error.InvalidLine;

	if (std.mem.startsWith(u8, trimmed, "allow ")) {
		const cidr = std.mem.trim(u8, trimmed[6..], " \t");
		return .{ .action = .allow, .cidr = cidr };
	}
	if (std.mem.startsWith(u8, trimmed, "deny ")) {
		const cidr = std.mem.trim(u8, trimmed[5..], " \t");
		return .{ .action = .deny, .cidr = cidr };
	}
	return error.InvalidLine;
}

/// Read action+cidr from a rule object. Returns null for malformed objects.
pub fn ruleAction(obj: std.json.ObjectMap) ?Pair {
	if (obj.get("allow")) |v| {
		if (v == .string) return .{ .action = .allow, .cidr = v.string };
	}
	if (obj.get("deny")) |v| {
		if (v == .string) return .{ .action = .deny, .cidr = v.string };
	}
	return null;
}

/// Optional comment string from a rule object.
pub fn ruleComment(obj: std.json.ObjectMap) ?[]const u8 {
	if (obj.get("comment")) |v| {
		if (v == .string) return v.string;
	}
	return null;
}
