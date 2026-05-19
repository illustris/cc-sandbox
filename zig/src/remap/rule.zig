// Remap rule operations on a std.json.Array of rule objects. Each object
// has shape:
//   {"from": "tcp 0.0.0.0/0:443", "to": "tcp 127.0.0.1:18080", "comment"?: "..."}
// The "from" and "to" strings are validated together by feeding the
// concatenation through filter.parseRemapLine -- the same parser the
// LD_PRELOAD shim uses to load the runtime file -- so the CLI cannot
// admit a rule that the shim won't accept.

const std = @import("std");
const filter = @import("filter");

pub const Mutation = error{
	IndexOutOfRange,
	InvalidSpec,
	InvalidLine,
	OutOfMemory,
};

pub fn newRuleObject(allocator: std.mem.Allocator, from: []const u8, to: []const u8) !std.json.Value {
	var obj: std.json.ObjectMap = .empty;
	const from_dup = try allocator.dupe(u8, from);
	const to_dup = try allocator.dupe(u8, to);
	try obj.put(allocator, try allocator.dupe(u8, "from"), .{ .string = from_dup });
	try obj.put(allocator, try allocator.dupe(u8, "to"), .{ .string = to_dup });
	return .{ .object = obj };
}

/// Validate a (from, to) pair by reassembling the runtime-format line
/// and feeding it through the shim's parser. Returns true iff the line
/// would parse cleanly.
pub fn validateSpec(from: []const u8, to: []const u8) bool {
	var buf: [256]u8 = undefined;
	const line = std.fmt.bufPrint(&buf, "remap {s} -> {s}", .{ from, to }) catch return false;
	return filter.parseRemapLine(line) != null;
}

pub fn append(allocator: std.mem.Allocator, arr: *std.json.Array, from: []const u8, to: []const u8) !usize {
	if (!validateSpec(from, to)) return error.InvalidSpec;
	const obj = try newRuleObject(allocator, from, to);
	try arr.append(obj);
	return arr.items.len;
}

pub fn insertAt(allocator: std.mem.Allocator, arr: *std.json.Array, pos: usize, from: []const u8, to: []const u8) !void {
	if (pos < 1 or pos > arr.items.len + 1) return error.IndexOutOfRange;
	if (!validateSpec(from, to)) return error.InvalidSpec;
	const obj = try newRuleObject(allocator, from, to);
	try arr.insert(pos - 1, obj);
}

pub fn delete(arr: *std.json.Array, index: usize) !void {
	if (index < 1 or index > arr.items.len) return error.IndexOutOfRange;
	_ = arr.orderedRemove(index - 1);
}

pub const Pair = struct {
	from: []const u8,
	to: []const u8,
};

pub fn replaceAll(allocator: std.mem.Allocator, arr: *std.json.Array, items: []const Pair) !void {
	arr.clearRetainingCapacity();
	for (items) |p| {
		if (!validateSpec(p.from, p.to)) return error.InvalidSpec;
		const obj = try newRuleObject(allocator, p.from, p.to);
		try arr.append(obj);
	}
}

/// Parse a single `set` input line of the form `FROM -> TO`, where each
/// side is the same syntax as `remap add` takes (e.g.
/// "tcp 0.0.0.0/0:443"). Empty/comment lines return null; bad lines
/// raise error.InvalidLine.
pub fn parseSetLine(line: []const u8) !?Pair {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;
	const arrow = std.mem.indexOf(u8, trimmed, "->") orelse return error.InvalidLine;
	const from = std.mem.trim(u8, trimmed[0..arrow], " \t");
	const to = std.mem.trim(u8, trimmed[arrow + 2 ..], " \t");
	if (!validateSpec(from, to)) return error.InvalidLine;
	return .{ .from = from, .to = to };
}

pub fn ruleSpec(obj: std.json.ObjectMap) ?Pair {
	const from_v = obj.get("from") orelse return null;
	const to_v = obj.get("to") orelse return null;
	if (from_v != .string or to_v != .string) return null;
	return .{ .from = from_v.string, .to = to_v.string };
}

pub fn ruleComment(obj: std.json.ObjectMap) ?[]const u8 {
	if (obj.get("comment")) |v| {
		if (v == .string) return v.string;
	}
	return null;
}

// --- Tests ---

const t = std.testing;

test "newRuleObject builds the right shape" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const v = try newRuleObject(arena.allocator(), "tcp 0.0.0.0/0:443", "tcp 127.0.0.1:18080");
	try t.expect(v == .object);
	try t.expectEqualStrings("tcp 0.0.0.0/0:443", v.object.get("from").?.string);
	try t.expectEqualStrings("tcp 127.0.0.1:18080", v.object.get("to").?.string);
}

test "validateSpec accepts well-formed, rejects malformed" {
	try t.expect(validateSpec("tcp 0.0.0.0/0:443", "tcp 127.0.0.1:18080"));
	try t.expect(validateSpec("tcp 1.2.3.0/24:80", "tcp 10.0.0.1:8080"));
	// missing proto on the LHS
	try t.expect(!validateSpec("0.0.0.0/0:443", "tcp 127.0.0.1:18080"));
	// missing port on the LHS
	try t.expect(!validateSpec("tcp 0.0.0.0/0", "tcp 127.0.0.1:18080"));
	// UDP rejected in v1
	try t.expect(!validateSpec("udp 0.0.0.0/0:53", "udp 127.0.0.1:1053"));
	// target with a CIDR prefix wider than /32 rejected (single host only)
	try t.expect(!validateSpec("tcp 0.0.0.0/0:443", "tcp 127.0.0.0/24:18080"));
}

test "parseSetLine valid" {
	const p = (try parseSetLine("tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080")).?;
	try t.expectEqualStrings("tcp 0.0.0.0/0:443", p.from);
	try t.expectEqualStrings("tcp 127.0.0.1:18080", p.to);
}

test "parseSetLine valid with extra whitespace" {
	const p = (try parseSetLine("\ttcp 0.0.0.0/0:443  ->  tcp 127.0.0.1:18080\t")).?;
	try t.expectEqualStrings("tcp 0.0.0.0/0:443", p.from);
	try t.expectEqualStrings("tcp 127.0.0.1:18080", p.to);
}

test "parseSetLine empty + comment lines" {
	try t.expect((try parseSetLine("")) == null);
	try t.expect((try parseSetLine("  ")) == null);
	try t.expect((try parseSetLine("# remap https")) == null);
}

test "parseSetLine rejects missing arrow / bad specs" {
	try t.expectError(error.InvalidLine, parseSetLine("tcp 0.0.0.0/0:443  tcp 127.0.0.1:18080"));
	try t.expectError(error.InvalidLine, parseSetLine("garbage -> tcp 127.0.0.1:18080"));
	try t.expectError(error.InvalidLine, parseSetLine("tcp 0.0.0.0/0:443 -> garbage"));
}
