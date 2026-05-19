// Argument parser for `cogbox remap`. Shape mirrors `cogbox rules` so
// the operator's mental model is identical (--at insertion, 1-based
// indices, set-from-stdin, etc.).
//
//   cogbox remap --config CFG --runtime RT list
//   cogbox remap --config CFG --runtime RT add FROM TO [--at N]
//   cogbox remap --config CFG --runtime RT del INDEX
//   cogbox remap --config CFG --runtime RT set                 (reads stdin)
//
// FROM and TO are single arguments in the same syntax that the runtime
// rules file uses, e.g. "tcp 0.0.0.0/0:443" and "tcp 127.0.0.1:18080".

const std = @import("std");

pub const Cmd = union(enum) {
	list,
	add: AddArgs,
	del: DelArgs,
	set,
};

pub const AddArgs = struct {
	from: []const u8,
	to: []const u8,
	pos: ?usize = null, // 1-based; null = append
};

pub const DelArgs = struct {
	index: usize, // 1-based
};

pub const Args = struct {
	config_path: []const u8,
	runtime_path: []const u8,
	cmd: Cmd,
};

pub const ParseError = error{
	MissingConfig,
	MissingRuntime,
	MissingSubcommand,
	UnknownSubcommand,
	InvalidArgs,
	InvalidIndex,
};

pub fn parse(argv: []const []const u8) ParseError!Args {
	var cfg: ?[]const u8 = null;
	var rt: ?[]const u8 = null;
	var i: usize = 0;

	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--config")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			cfg = argv[i];
		} else if (std.mem.eql(u8, a, "--runtime")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			rt = argv[i];
		} else if (std.mem.startsWith(u8, a, "--")) {
			return error.InvalidArgs;
		} else {
			break;
		}
	}

	const cfg_path = cfg orelse return error.MissingConfig;
	const rt_path = rt orelse return error.MissingRuntime;
	if (i >= argv.len) return error.MissingSubcommand;

	const sub = argv[i];
	i += 1;
	const sub_args = argv[i..];

	if (std.mem.eql(u8, sub, "list")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .list };
	}
	if (std.mem.eql(u8, sub, "set")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .set };
	}
	if (std.mem.eql(u8, sub, "add")) return parseAdd(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "del")) return parseDel(cfg_path, rt_path, sub_args);
	return error.UnknownSubcommand;
}

fn parseAdd(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len < 2) return error.InvalidArgs;
	const from = args[0];
	const to = args[1];
	var pos: ?usize = null;

	var i: usize = 2;
	while (i < args.len) : (i += 1) {
		if (std.mem.eql(u8, args[i], "--at")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			pos = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidIndex;
			if (pos.? == 0) return error.InvalidIndex;
		} else {
			return error.InvalidArgs;
		}
	}

	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .add = .{ .from = from, .to = to, .pos = pos } },
	};
}

fn parseDel(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	const idx = std.fmt.parseInt(usize, args[0], 10) catch return error.InvalidIndex;
	if (idx == 0) return error.InvalidIndex;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .del = .{ .index = idx } },
	};
}

// --- Tests ---

const t = std.testing;

fn argvOf(items: []const []const u8) []const []const u8 {
	return items;
}

test "list parses" {
	const a = try parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "list" }));
	try t.expect(a.cmd == .list);
}

test "add without --at" {
	const a = try parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "add", "tcp 0.0.0.0/0:443", "tcp 127.0.0.1:18080" }));
	try t.expect(a.cmd == .add);
	try t.expectEqualStrings("tcp 0.0.0.0/0:443", a.cmd.add.from);
	try t.expectEqualStrings("tcp 127.0.0.1:18080", a.cmd.add.to);
	try t.expect(a.cmd.add.pos == null);
}

test "add with --at" {
	const a = try parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "add", "tcp 0.0.0.0/0:443", "tcp 127.0.0.1:18080", "--at", "3" }));
	try t.expectEqual(@as(?usize, 3), a.cmd.add.pos);
}

test "add rejects --at 0 and missing TO" {
	try t.expectError(error.InvalidIndex, parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "add", "tcp 0.0.0.0/0:443", "tcp 127.0.0.1:18080", "--at", "0" })));
	try t.expectError(error.InvalidArgs, parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "add", "tcp 0.0.0.0/0:443" })));
}

test "del with valid index" {
	const a = try parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "del", "2" }));
	try t.expectEqual(@as(usize, 2), a.cmd.del.index);
}

test "unknown subcommand" {
	try t.expectError(error.UnknownSubcommand, parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "blast" })));
}

test "set takes no extra args" {
	const a = try parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "set" }));
	try t.expect(a.cmd == .set);
	try t.expectError(error.InvalidArgs, parse(argvOf(&.{ "--config", "/c", "--runtime", "/r", "set", "extra" })));
}
