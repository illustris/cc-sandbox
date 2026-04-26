const std = @import("std");
const cli = @import("cli.zig");
const config = @import("config.zig");
const rule = @import("rule.zig");
const reload = @import("reload.zig");

pub fn main(init: std.process.Init) !void {
	const allocator = init.gpa;
	const io = init.io;

	const argv_full = try init.minimal.args.toSlice(init.arena.allocator());
	const argv: []const []const u8 = blk: {
		const slice = try init.arena.allocator().alloc([]const u8, argv_full.len);
		for (argv_full, 0..) |a, i| slice[i] = a;
		break :blk if (slice.len > 0) slice[1..] else &.{};
	};

	const args = cli.parse(argv) catch |err| {
		try writeStderr(io, try std.fmt.allocPrint(allocator, "Error: argument error: {s}\n", .{@errorName(err)}));
		std.process.exit(2);
	};

	var loaded = config.load(allocator, io, args.config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{args.config_path}),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{args.config_path}),
		else => return err,
	};
	defer loaded.deinit();

	const rules_arr = loaded.rules() catch |err| switch (err) {
		error.NotInRulesMode => return die(
			allocator,
			io,
			"instance is not in rules mode. Set network to rules mode first: edit {s} or reinit with --network rules.",
			.{args.config_path},
		),
		else => return err,
	};

	switch (args.cmd) {
		.list => try cmdList(allocator, io, rules_arr.*),
		.add => |a| try cmdAdd(allocator, io, args, rules_arr, a, &loaded),
		.del => |d| try cmdDel(allocator, io, args, rules_arr, d, &loaded),
		.set => try cmdSet(allocator, io, args, rules_arr, &loaded),
	}
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, rules_arr: std.json.Array) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

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
		try out.appendSlice(allocator, p.cidr);
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
	rules_arr: *std.json.Array,
	a: cli.AddArgs,
	loaded: *config.Loaded,
) !void {
	const tree_alloc = loaded.treeAllocator();
	if (a.pos) |p| {
		rule.insertAt(tree_alloc, rules_arr, p, a.action, a.cidr) catch |err| switch (err) {
			error.IndexOutOfRange => return die(allocator, io, "position out of range (must be 1..{d})", .{rules_arr.items.len + 1}),
			error.InvalidCidr => return die(allocator, io, "invalid CIDR: {s}", .{a.cidr}),
			else => return err,
		};
	} else {
		_ = rule.append(tree_alloc, rules_arr, a.action, a.cidr) catch |err| switch (err) {
			error.InvalidCidr => return die(allocator, io, "invalid CIDR: {s}", .{a.cidr}),
			else => return err,
		};
	}

	try config.save(allocator, io, args.config_path, loaded.root().*);
	const action_str = switch (a.action) {
		.allow => "allow",
		.deny => "deny",
	};
	if (a.pos) |p| {
		try announce(allocator, io, "Added: {s} {s} at position {d}", .{ action_str, a.cidr, p });
	} else {
		try announce(allocator, io, "Added: {s} {s}", .{ action_str, a.cidr });
	}
	try maybeReload(allocator, io, args.runtime_path, rules_arr.*);
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
		return die(allocator, io, "index {d} out of range (1..{d})", .{ d.index, rules_arr.items.len });
	};

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Deleted rule {d}.", .{d.index});
	try maybeReload(allocator, io, args.runtime_path, rules_arr.*);
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
	var owned_storage: std.ArrayList(u8) = .empty;
	defer owned_storage.deinit(allocator);
	var owned_offsets: std.ArrayList(struct { off: usize, len: usize }) = .empty;
	defer owned_offsets.deinit(allocator);

	while (true) {
		const maybe_line = try stdin_reader.interface.takeDelimiter('\n');
		const line = maybe_line orelse break;
		const parsed = rule.parseSetLine(line) catch {
			return die(allocator, io, "invalid line: {s}", .{line});
		};
		if (parsed) |p| {
			const off = owned_storage.items.len;
			try owned_storage.appendSlice(allocator, p.cidr);
			try owned_offsets.append(allocator, .{ .off = off, .len = p.cidr.len });
			try pairs.append(allocator, .{ .action = p.action, .cidr = "" });
		}
	}
	for (pairs.items, owned_offsets.items) |*p, o| {
		p.cidr = owned_storage.items[o.off .. o.off + o.len];
	}

	try rule.replaceAll(loaded.treeAllocator(), rules_arr, pairs.items);
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Rules replaced.", .{});
	try maybeReload(allocator, io, args.runtime_path, rules_arr.*);
}

fn maybeReload(allocator: std.mem.Allocator, io: std.Io, runtime_path: []const u8, rules_arr: std.json.Array) !void {
	const pid_path = try std.fs.path.join(allocator, &.{ runtime_path, "passt.pid" });
	defer allocator.free(pid_path);
	std.Io.Dir.cwd().access(io, pid_path, .{}) catch return;

	try reload.writeRuntimeRules(allocator, io, runtime_path, rules_arr);
	const sent = try reload.maybeSignalPasst(allocator, io, runtime_path);
	if (sent) try announce(allocator, io, "Rules reloaded.", .{});
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

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) noreturn {
	const msg = std.fmt.allocPrint(allocator, "Error: " ++ fmt ++ "\n", args) catch "Error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(1);
}
