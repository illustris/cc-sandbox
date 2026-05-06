// Top-level dispatcher for the cogbox CLI.

const std = @import("std");
const util = @import("util.zig");
const help = @import("help.zig");
const exit_codes = @import("exit.zig");
const paths = @import("paths.zig");
const preflight = @import("preflight.zig");

const list_verb = @import("verbs/list.zig");
const status_verb = @import("verbs/status.zig");
const stop_verb = @import("verbs/stop.zig");
const restart_verb = @import("verbs/restart.zig");
const ssh_verb = @import("verbs/ssh.zig");
const rules_verb = @import("verbs/rules.zig");
const run_verb = @import("verbs/run.zig");
const start_verb = @import("verbs/start.zig");

const KNOWN_VERBS = [_][]const u8{
	"run", "start", "stop", "restart", "status", "list", "init", "ssh", "rules", "help",
};

pub fn main(init: std.process.Init) !void {
	const allocator = init.gpa;
	const io = init.io;
	const env = init.environ_map;

	const argv_full = try init.minimal.args.toSlice(init.arena.allocator());
	const argv: []const []const u8 = blk: {
		const slice = try init.arena.allocator().alloc([]const u8, argv_full.len);
		for (argv_full, 0..) |a, i| slice[i] = a;
		break :blk if (slice.len > 0) slice[1..] else &.{};
	};

	// Top-level --help / -h before any verb resolution. This way
	// `cogbox --help` and `cogbox` both behave intuitively.
	if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
		try help.print(io, help.TOP_LEVEL);
		return;
	}

	// Reject removed flags with a clear redirect.
	if (argv.len > 0) {
		if (std.mem.eql(u8, argv[0], "--list")) {
			util.die(allocator, io, null, exit_codes.usage, "--list was removed; use 'cogbox list'", .{});
		}
		if (std.mem.eql(u8, argv[0], "--init-only")) {
			util.die(allocator, io, null, exit_codes.usage, "--init-only was removed; use 'cogbox init'", .{});
		}
	}

	// Determine verb. If argv[0] is a known verb, that's the verb.
	// Otherwise (no args, or first arg looks like a flag), default to `run`.
	var verb: []const u8 = "run";
	var rest = argv;
	if (argv.len > 0) {
		if (isKnownVerb(argv[0])) {
			verb = argv[0];
			rest = argv[1..];
		}
	}

	// Resolve XDG paths and check for legacy migration before dispatch.
	var p = paths.resolve(allocator, io, env) catch |err| {
		util.die(allocator, io, null, exit_codes.software, "failed to resolve paths: {s}", .{@errorName(err)});
	};
	defer p.deinit();

	try preflight.run(allocator, io, env, &p);

	if (std.mem.eql(u8, verb, "help")) {
		if (rest.len == 0) {
			try help.print(io, help.TOP_LEVEL);
			return;
		}
		const body = help.forVerb(rest[0]) orelse {
			util.die(allocator, io, null, exit_codes.usage, "unknown verb '{s}'", .{rest[0]});
		};
		try help.print(io, body);
		return;
	}

	if (std.mem.eql(u8, verb, "list")) return list_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "status")) return status_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "stop")) return stop_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "restart")) return restart_verb.run(allocator, io, env, &p, rest);
	if (std.mem.eql(u8, verb, "ssh")) return ssh_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "rules")) return rules_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "init")) return run_verb.run(allocator, io, env, rest, "init", true);
	if (std.mem.eql(u8, verb, "run")) return run_verb.run(allocator, io, env, rest, "run", false);
	if (std.mem.eql(u8, verb, "start")) return start_verb.run(allocator, io, env, &p, rest);

	util.die(allocator, io, null, exit_codes.usage, "unknown verb '{s}'", .{verb});
}

fn isKnownVerb(s: []const u8) bool {
	for (KNOWN_VERBS) |v| {
		if (std.mem.eql(u8, v, s)) return true;
	}
	return false;
}
