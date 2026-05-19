// `cogbox remap` verb dispatcher. Shares config/save/reload with the
// `rules` verb via the rules_module re-exports, so a `remap` edit also
// re-renders the runtime rules file (which carries BOTH CIDR allow/deny
// and remap lines) and SIGUSR1s a running passt.

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
		try writeStderr(io, try std.fmt.allocPrint(allocator, "cogbox remap: error: {s}\n", .{@errorName(err)}));
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

	const remap_arr = try ensureRemapArray(net, loaded.treeAllocator());

	switch (args.cmd) {
		.list => try cmdList(allocator, io, remap_arr.*),
		.add => |a| try cmdAdd(allocator, io, args, remap_arr, a, &loaded),
		.del => |d| try cmdDel(allocator, io, args, remap_arr, d, &loaded),
		.set => try cmdSet(allocator, io, args, remap_arr, &loaded),
	}
}

/// Ensure .network.remap exists and is an array; create empty if missing.
fn ensureRemapArray(net: *std.json.Value, arena: std.mem.Allocator) !*std.json.Array {
	if (net.object.getPtr("remap") == null) {
		try net.object.put(arena, try arena.dupe(u8, "remap"), .{ .array = std.json.Array.init(arena) });
	}
	const v = net.object.getPtr("remap").?;
	if (v.* != .array) return error.InvalidJson;
	return &v.array;
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, remap_arr: std.json.Array) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	for (remap_arr.items, 0..) |r, i| {
		if (r != .object) continue;
		var line_buf: [32]u8 = undefined;
		const idx_str = std.fmt.bufPrint(&line_buf, "{d}: ", .{i + 1}) catch unreachable;
		try out.appendSlice(allocator, idx_str);

		const p = rule.ruleSpec(r.object) orelse {
			try out.appendSlice(allocator, "unknown\n");
			continue;
		};
		try out.appendSlice(allocator, p.from);
		try out.appendSlice(allocator, " -> ");
		try out.appendSlice(allocator, p.to);
		if (rule.ruleComment(r.object)) |c| {
			try out.appendSlice(allocator, "  # ");
			try out.appendSlice(allocator, c);
		}
		try out.append(allocator, '\n');
	}

	try writeStdout(io, out.items);
}

fn cmdAdd(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	remap_arr: *std.json.Array,
	a: cli.AddArgs,
	loaded: *config.Loaded,
) !void {
	const tree_alloc = loaded.treeAllocator();
	if (a.pos) |p| {
		rule.insertAt(tree_alloc, remap_arr, p, a.from, a.to) catch |err| switch (err) {
			error.IndexOutOfRange => return die(allocator, io, "position out of range (must be 1..{d})", .{remap_arr.items.len + 1}, 65),
			error.InvalidSpec => return die(allocator, io, "invalid remap spec: {s} -> {s}", .{ a.from, a.to }, 65),
			else => return err,
		};
	} else {
		_ = rule.append(tree_alloc, remap_arr, a.from, a.to) catch |err| switch (err) {
			error.InvalidSpec => return die(allocator, io, "invalid remap spec: {s} -> {s}", .{ a.from, a.to }, 65),
			else => return err,
		};
	}

	try config.save(allocator, io, args.config_path, loaded.root().*);
	if (a.pos) |p| {
		try announce(allocator, io, "Added: {s} -> {s} at position {d}", .{ a.from, a.to, p });
	} else {
		try announce(allocator, io, "Added: {s} -> {s}", .{ a.from, a.to });
	}
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdDel(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	remap_arr: *std.json.Array,
	d: cli.DelArgs,
	loaded: *config.Loaded,
) !void {
	rule.delete(remap_arr, d.index) catch {
		return die(allocator, io, "index {d} out of range (1..{d})", .{ d.index, remap_arr.items.len }, 65);
	};

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Deleted remap rule {d}.", .{d.index});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdSet(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	remap_arr: *std.json.Array,
	loaded: *config.Loaded,
) !void {
	const stdin = std.Io.File.stdin();
	var stdin_buf: [4096]u8 = undefined;
	var stdin_reader = stdin.readerStreaming(io, &stdin_buf);

	var pairs: std.ArrayList(rule.Pair) = .empty;
	defer pairs.deinit(allocator);
	var owned: std.ArrayList(u8) = .empty;
	defer owned.deinit(allocator);
	const Slot = struct { from_off: usize, from_len: usize, to_off: usize, to_len: usize };
	var slots: std.ArrayList(Slot) = .empty;
	defer slots.deinit(allocator);

	while (true) {
		const maybe_line = try stdin_reader.interface.takeDelimiter('\n');
		const line = maybe_line orelse break;
		const parsed = rule.parseSetLine(line) catch {
			return die(allocator, io, "invalid line: {s}", .{line}, 65);
		};
		if (parsed) |p| {
			const from_off = owned.items.len;
			try owned.appendSlice(allocator, p.from);
			const to_off = owned.items.len;
			try owned.appendSlice(allocator, p.to);
			try slots.append(allocator, .{
				.from_off = from_off,
				.from_len = p.from.len,
				.to_off = to_off,
				.to_len = p.to.len,
			});
			try pairs.append(allocator, .{ .from = "", .to = "" });
		}
	}
	for (pairs.items, slots.items) |*p, s| {
		p.from = owned.items[s.from_off .. s.from_off + s.from_len];
		p.to = owned.items[s.to_off .. s.to_off + s.to_len];
	}

	try rule.replaceAll(loaded.treeAllocator(), remap_arr, pairs.items);
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Remap rules replaced.", .{});
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
	const msg = std.fmt.allocPrint(allocator, "cogbox remap: error: " ++ fmt ++ "\n", args) catch "cogbox remap: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}
