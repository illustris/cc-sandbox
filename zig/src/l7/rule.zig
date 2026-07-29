// Rule operations on the `.network.l7.rules` array. Each rule object has
// exactly one of `allow` or `deny` keyed to an SNI/Host pattern (the same
// grammar as DNS patterns: exact / *.suffix / *), and may optionally carry a
// `comment` plus the tier fields (`path`, `terminate`, `insecure_upstream`,
// `passthrough`) written by the corresponding `l7 add` flags.

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

/// Optional attributes of an l7 rule object beyond its action+host. Grouped so
/// the tier flags (`terminate`/`insecure`/`passthrough`) and the request-match
/// fields (`path`/`methods`/`exact`/`service`) don't sprawl the call signatures.
pub const Attrs = struct {
	path: ?[]const u8 = null,
	terminate: bool = false,
	insecure: bool = false,
	passthrough: bool = false,
	// Uppercase comma-separated HTTP-method constraint (`GET` / `GET,POST`).
	methods: ?[]const u8 = null,
	// Match `path` by full equality instead of the default boundary-aware prefix.
	exact: bool = false,
	// git smart-HTTP service constraint (git-upload-pack / git-receive-pack).
	service: ?[]const u8 = null,
};

pub fn newRuleObject(allocator: std.mem.Allocator, action: Action, host: []const u8, attrs: Attrs) !std.json.Value {
	var obj: std.json.ObjectMap = .empty;
	const action_key = try allocator.dupe(u8, switch (action) {
		.allow => "allow",
		.deny => "deny",
	});
	const host_dup = try allocator.dupe(u8, host);
	try obj.put(allocator, action_key, .{ .string = host_dup });
	if (attrs.methods) |m| {
		try obj.put(allocator, try allocator.dupe(u8, "methods"), .{ .string = try allocator.dupe(u8, m) });
	}
	if (attrs.path) |p| {
		try obj.put(allocator, try allocator.dupe(u8, "path"), .{ .string = try allocator.dupe(u8, p) });
	}
	if (attrs.exact) {
		try obj.put(allocator, try allocator.dupe(u8, "pathmode"), .{ .string = try allocator.dupe(u8, "exact") });
	}
	if (attrs.service) |s| {
		try obj.put(allocator, try allocator.dupe(u8, "service"), .{ .string = try allocator.dupe(u8, s) });
	}
	// A path implies terminate; only emit the flag when there's no path
	// carrying the same signal, to keep the object minimal.
	if (attrs.terminate and attrs.path == null) {
		try obj.put(allocator, try allocator.dupe(u8, "terminate"), .{ .bool = true });
	}
	if (attrs.insecure) {
		try obj.put(allocator, try allocator.dupe(u8, "insecure_upstream"), .{ .bool = true });
	}
	if (attrs.passthrough) {
		try obj.put(allocator, try allocator.dupe(u8, "passthrough"), .{ .bool = true });
	}
	return .{ .object = obj };
}

pub fn append(allocator: std.mem.Allocator, arr: *std.json.Array, action: Action, host: []const u8, attrs: Attrs) !usize {
	if (!validateHost(host)) return error.InvalidHost;
	const obj = try newRuleObject(allocator, action, host, attrs);
	try arr.append(obj);
	return arr.items.len;
}

pub fn insertAt(allocator: std.mem.Allocator, arr: *std.json.Array, pos: usize, action: Action, host: []const u8, attrs: Attrs) !void {
	if (pos < 1 or pos > arr.items.len + 1) return error.IndexOutOfRange;
	if (!validateHost(host)) return error.InvalidHost;
	const obj = try newRuleObject(allocator, action, host, attrs);
	try arr.insert(pos - 1, obj);
}

pub fn delete(arr: *std.json.Array, index: usize) !void {
	if (index < 1 or index > arr.items.len) return error.IndexOutOfRange;
	_ = arr.orderedRemove(index - 1);
}

/// Remove every rule object tagged `"plugin": <tag>`. Returns the count
/// removed. Used by `l7 clear --plugin <tag>` to replace a whole tagged set
/// (e.g. `git-grants`) without index races.
pub fn deleteByPlugin(arr: *std.json.Array, tag: []const u8) usize {
	var removed: usize = 0;
	var i: usize = 0;
	while (i < arr.items.len) {
		const item = arr.items[i];
		if (item == .object) {
			if (item.object.get("plugin")) |v| {
				if (v == .string and std.mem.eql(u8, v.string, tag)) {
					_ = arr.orderedRemove(i);
					removed += 1;
					continue;
				}
			}
		}
		i += 1;
	}
	return removed;
}

pub fn replaceAll(allocator: std.mem.Allocator, arr: *std.json.Array, items: []const Pair) !void {
	arr.clearRetainingCapacity();
	for (items) |p| {
		if (!validateHost(p.host)) return error.InvalidHost;
		const obj = try newRuleObject(allocator, p.action, p.host, .{});
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

/// Read action+host from a rule object, ignoring the tier fields (the
/// `list` view renders those markers separately).
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

// --- Tests ---

const t = std.testing;

test "newRuleObject emits methods / pathmode:exact / service" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const v = try newRuleObject(a, .allow, "git.example.internal", .{
		.path = "/g/p.git/git-upload-pack",
		.methods = "POST",
		.exact = true,
		.service = "git-upload-pack",
	});
	const o = v.object;
	try t.expectEqualStrings("git.example.internal", o.get("allow").?.string);
	try t.expectEqualStrings("POST", o.get("methods").?.string);
	try t.expectEqualStrings("/g/p.git/git-upload-pack", o.get("path").?.string);
	try t.expectEqualStrings("exact", o.get("pathmode").?.string);
	try t.expectEqualStrings("git-upload-pack", o.get("service").?.string);
	// A bare rule carries none of the new keys.
	const bare = try newRuleObject(a, .allow, "plain.test", .{});
	try t.expect(bare.object.get("methods") == null);
	try t.expect(bare.object.get("pathmode") == null);
	try t.expect(bare.object.get("service") == null);
}

test "deleteByPlugin removes only the tagged rules" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	var arr = std.json.Array.init(a);
	_ = try append(a, &arr, .allow, "a.test", .{});
	_ = try append(a, &arr, .allow, "git.example.internal", .{ .path = "/g/p.git/git-upload-pack" });
	// tag two rules with git-grants, one with a different tag, leave one untagged
	try arr.items[1].object.put(a, "plugin", .{ .string = "git-grants" });
	_ = try append(a, &arr, .allow, "b.test", .{});
	try arr.items[2].object.put(a, "plugin", .{ .string = "obs-plugin" });
	_ = try append(a, &arr, .deny, "c.test", .{});
	try arr.items[3].object.put(a, "plugin", .{ .string = "git-grants" });

	const removed = deleteByPlugin(&arr, "git-grants");
	try t.expectEqual(@as(usize, 2), removed);
	try t.expectEqual(@as(usize, 2), arr.items.len);
	// the untagged rule and the differently-tagged rule survive
	try t.expectEqualStrings("a.test", arr.items[0].object.get("allow").?.string);
	try t.expectEqualStrings("obs-plugin", arr.items[1].object.get("plugin").?.string);
}
