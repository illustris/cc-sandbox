// `cogbox l7` verb dispatcher. Manages `.network.l7` (an object with `mode`
// and a `rules` array of SNI/Host allow/deny entries). Shares config load/
// save + the shared reload path with `rules`/`remap` via rules_module, so an
// l7 edit re-renders BOTH the netfilter-rules funnel lines and the proxy's
// l7-rules file, and signals passt (SIGUSR1) + the L7 proxy (SIGHUP).

const std = @import("std");
pub const cli = @import("cli.zig");
pub const rule = @import("rule.zig");

const rules_module = @import("rules_module");
const config = rules_module.config;

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	config_path: []const u8,
	runtime_path: []const u8,
	rest: []const []const u8,
) !void {
	var argv = try allocator.alloc([]const u8, 4 + rest.len);
	defer allocator.free(argv);
	argv[0] = "--config";
	argv[1] = config_path;
	argv[2] = "--runtime";
	argv[3] = runtime_path;
	for (rest, 0..) |a, i| argv[4 + i] = a;

	const args = cli.parse(argv) catch |err| {
		try writeStderr(io, try std.fmt.allocPrint(allocator, "cogbox l7: error: {s}\n", .{@errorName(err)}));
		std.process.exit(64);
	};

	var loaded = config.load(allocator, io, args.config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{args.config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{args.config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	const net = loaded.network() catch |err| switch (err) {
		error.NotInRulesMode => return die(
			allocator,
			io,
			"instance is not in rules mode. Set network to rules mode first: edit {s} or reinit with --network rules.",
			.{args.config_path},
			65,
		),
		else => return err,
	};

	const l7 = try ensureL7Object(net, loaded.treeAllocator());
	const rules_arr = &l7.object.getPtr("rules").?.array;

	switch (args.cmd) {
		.list => try cmdList(allocator, io, l7.*, rules_arr.*),
		.add => |a| try cmdAdd(allocator, io, args, rules_arr, a, &loaded),
		.del => |d| try cmdDel(allocator, io, args, rules_arr, d, &loaded),
		.set => try cmdSet(allocator, io, args, rules_arr, &loaded),
		.mode => |m| try cmdMode(allocator, io, args, l7, m, &loaded),
	}
}

/// Ensure `.network.l7` is `{ "mode": "passthrough", "rules": [] }`-shaped.
fn ensureL7Object(net: *std.json.Value, arena: std.mem.Allocator) !*std.json.Value {
	if (net.object.getPtr("l7") == null) {
		var obj: std.json.ObjectMap = .empty;
		try obj.put(arena, try arena.dupe(u8, "mode"), .{ .string = try arena.dupe(u8, "passthrough") });
		try obj.put(arena, try arena.dupe(u8, "rules"), .{ .array = std.json.Array.init(arena) });
		try net.object.put(arena, try arena.dupe(u8, "l7"), .{ .object = obj });
	}
	const l7 = net.object.getPtr("l7").?;
	if (l7.* != .object) return error.InvalidJson;
	if (l7.object.getPtr("rules") == null) {
		try l7.object.put(arena, try arena.dupe(u8, "rules"), .{ .array = std.json.Array.init(arena) });
	}
	if (l7.object.getPtr("rules").?.* != .array) return error.InvalidJson;
	return l7;
}

fn modeTerminate(l7: std.json.Value) bool {
	if (l7.object.get("mode")) |m| {
		if (m == .string and std.mem.eql(u8, m.string, "terminate")) return true;
	}
	return false;
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, l7: std.json.Value, rules_arr: std.json.Array) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	try out.appendSlice(allocator, "mode: ");
	try out.appendSlice(allocator, if (modeTerminate(l7)) "terminate\n" else "passthrough\n");

	for (rules_arr.items, 0..) |r, i| {
		if (r != .object) continue;
		var line_buf: [32]u8 = undefined;
		const idx_str = std.fmt.bufPrint(&line_buf, "{d}: ", .{i + 1}) catch unreachable;
		try out.appendSlice(allocator, idx_str);

		const p = rule.ruleAction(r.object) orelse {
			try out.appendSlice(allocator, "unknown\n");
			continue;
		};
		try out.appendSlice(allocator, switch (p.action) {
			.allow => "allow ",
			.deny => "deny ",
		});
		try out.appendSlice(allocator, p.host);
		if (r.object.get("path")) |pv| {
			if (pv == .string) {
				try out.appendSlice(allocator, " ");
				try out.appendSlice(allocator, pv.string);
			}
		}
		if (r.object.get("terminate")) |tv| {
			if (tv == .bool and tv.bool) try out.appendSlice(allocator, " [terminate]");
		}
		if (rule.ruleComment(r.object)) |co| {
			try out.appendSlice(allocator, "  # ");
			try out.appendSlice(allocator, co);
		}
		try out.append(allocator, '\n');
	}

	try writeStdout(io, out.items);
}

fn cmdAdd(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	a: cli.AddArgs,
	loaded: *config.Loaded,
) !void {
	const tree_alloc = loaded.treeAllocator();
	if (a.pos) |p| {
		rule.insertAt(tree_alloc, rules_arr, p, a.action, a.host) catch |err| switch (err) {
			error.IndexOutOfRange => return die(allocator, io, "position out of range (must be 1..{d})", .{rules_arr.items.len + 1}, 65),
			error.InvalidHost => return die(allocator, io, "invalid host pattern: {s}", .{a.host}, 65),
			else => return err,
		};
	} else {
		_ = rule.append(tree_alloc, rules_arr, a.action, a.host) catch |err| switch (err) {
			error.InvalidHost => return die(allocator, io, "invalid host pattern: {s}", .{a.host}, 65),
			else => return err,
		};
	}

	try config.save(allocator, io, args.config_path, loaded.root().*);
	const action_str = switch (a.action) {
		.allow => "allow",
		.deny => "deny",
	};
	if (a.pos) |p| {
		try announce(allocator, io, "Added: {s} {s} at position {d}", .{ action_str, a.host, p });
	} else {
		try announce(allocator, io, "Added: {s} {s}", .{ action_str, a.host });
	}
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdDel(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	d: cli.DelArgs,
	loaded: *config.Loaded,
) !void {
	rule.delete(rules_arr, d.index) catch {
		return die(allocator, io, "index {d} out of range (1..{d})", .{ d.index, rules_arr.items.len }, 65);
	};

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Deleted l7 rule {d}.", .{d.index});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdSet(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	loaded: *config.Loaded,
) !void {
	const stdin = std.Io.File.stdin();
	var stdin_buf: [4096]u8 = undefined;
	var stdin_reader = stdin.readerStreaming(io, &stdin_buf);

	var pairs: std.ArrayList(rule.Pair) = .empty;
	defer pairs.deinit(allocator);
	var owned: std.ArrayList(u8) = .empty;
	defer owned.deinit(allocator);
	const Slot = struct { off: usize, len: usize };
	var slots: std.ArrayList(Slot) = .empty;
	defer slots.deinit(allocator);

	while (true) {
		const maybe_line = try stdin_reader.interface.takeDelimiter('\n');
		const line = maybe_line orelse break;
		const parsed = rule.parseSetLine(line) catch {
			return die(allocator, io, "invalid line: {s}", .{line}, 65);
		};
		if (parsed) |p| {
			const off = owned.items.len;
			try owned.appendSlice(allocator, p.host);
			try slots.append(allocator, .{ .off = off, .len = p.host.len });
			try pairs.append(allocator, .{ .action = p.action, .host = "" });
		}
	}
	for (pairs.items, slots.items) |*p, s| {
		p.host = owned.items[s.off .. s.off + s.len];
	}

	try rule.replaceAll(loaded.treeAllocator(), rules_arr, pairs.items);
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "L7 rules replaced.", .{});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdMode(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	l7: *std.json.Value,
	m: cli.ModeArgs,
	loaded: *config.Loaded,
) !void {
	if (m.terminate) {
		return die(
			allocator,
			io,
			"the terminating tier (TLS interception, path rules) is not available yet. v1 ships the passthrough (SNI/Host) tier only.",
			.{},
			65,
		);
	}
	const arena = loaded.treeAllocator();
	try l7.object.put(arena, try arena.dupe(u8, "mode"), .{ .string = try arena.dupe(u8, "passthrough") });
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "L7 mode set to passthrough.", .{});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn writeStdout(io: std.Io, bytes: []const u8) !void {
	const stdout = std.Io.File.stdout();
	var buf: [4096]u8 = undefined;
	var w = stdout.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn writeStderr(io: std.Io, bytes: []const u8) !void {
	const stderr = std.Io.File.stderr();
	var buf: [4096]u8 = undefined;
	var w = stderr.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn announce(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStdout(io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox l7: error: " ++ fmt ++ "\n", args) catch "cogbox l7: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}
