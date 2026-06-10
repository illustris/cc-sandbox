// Argument parser for `cogbox l7`. Mirrors `cogbox rules` so the operator's
// mental model is identical, with one extra subcommand (`mode`).
//
//   cogbox l7 --config CFG --runtime RT list
//   cogbox l7 --config CFG --runtime RT add allow|deny HOST [--at N]
//   cogbox l7 --config CFG --runtime RT del INDEX
//   cogbox l7 --config CFG --runtime RT set                 (reads stdin)
//   cogbox l7 --config CFG --runtime RT mode passthrough|terminate

const std = @import("std");
const rule = @import("rule.zig");

pub const Cmd = union(enum) {
	list,
	add: AddArgs,
	del: DelArgs,
	set,
	mode: ModeArgs,
};

pub const AddArgs = struct {
	action: rule.Action,
	host: []const u8,
	pos: ?usize = null, // 1-based; null = append
};

pub const DelArgs = struct {
	index: usize, // 1-based
};

pub const ModeArgs = struct {
	terminate: bool,
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
	InvalidAction,
	InvalidMode,
	InvalidIndex,
};

pub fn parse(argv: []const []const u8) ParseError!Args {
	var config: ?[]const u8 = null;
	var runtime: ?[]const u8 = null;
	var i: usize = 0;

	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--config")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			config = argv[i];
		} else if (std.mem.eql(u8, a, "--runtime")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			runtime = argv[i];
		} else if (std.mem.startsWith(u8, a, "--")) {
			return error.InvalidArgs;
		} else {
			break;
		}
	}

	const cfg_path = config orelse return error.MissingConfig;
	const rt_path = runtime orelse return error.MissingRuntime;
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
	if (std.mem.eql(u8, sub, "mode")) return parseMode(cfg_path, rt_path, sub_args);
	return error.UnknownSubcommand;
}

fn parseAdd(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len < 2) return error.InvalidArgs;
	const action = parseAction(args[0]) orelse return error.InvalidAction;
	const host = args[1];
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
		.cmd = .{ .add = .{ .action = action, .host = host, .pos = pos } },
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

fn parseMode(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	var terminate: bool = undefined;
	if (std.mem.eql(u8, args[0], "passthrough")) {
		terminate = false;
	} else if (std.mem.eql(u8, args[0], "terminate")) {
		terminate = true;
	} else {
		return error.InvalidMode;
	}
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .mode = .{ .terminate = terminate } },
	};
}

fn parseAction(s: []const u8) ?rule.Action {
	if (std.mem.eql(u8, s, "allow")) return .allow;
	if (std.mem.eql(u8, s, "deny")) return .deny;
	return null;
}

// --- Tests ---

const t = std.testing;

test "list parses" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "list" });
	try t.expect(a.cmd == .list);
}

test "add allow host without --at" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "vhost-a.test" });
	try t.expect(a.cmd == .add);
	try t.expectEqual(rule.Action.allow, a.cmd.add.action);
	try t.expectEqualStrings("vhost-a.test", a.cmd.add.host);
	try t.expect(a.cmd.add.pos == null);
}

test "add with --at" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "deny", "*.evil.test", "--at", "2" });
	try t.expectEqual(@as(?usize, 2), a.cmd.add.pos);
	try t.expectEqual(rule.Action.deny, a.cmd.add.action);
}

test "add rejects bad action and --at 0" {
	try t.expectError(error.InvalidAction, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "permit", "a.test" }));
	try t.expectError(error.InvalidIndex, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--at", "0" }));
}

test "del + mode parse" {
	const d = try parse(&.{ "--config", "/c", "--runtime", "/r", "del", "3" });
	try t.expectEqual(@as(usize, 3), d.cmd.del.index);
	const m = try parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "terminate" });
	try t.expect(m.cmd.mode.terminate);
	try t.expectError(error.InvalidMode, parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "sideways" }));
}

test "unknown subcommand" {
	try t.expectError(error.UnknownSubcommand, parse(&.{ "--config", "/c", "--runtime", "/r", "blast" }));
}
