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
const remap_verb = @import("verbs/remap.zig");
const l7_verb = @import("verbs/l7.zig");
const run_verb = @import("verbs/run.zig");
const rules_module = @import("rules_module");
const l7proxy_module = @import("l7proxy_module");
const filter_mod = @import("filter");
const start_verb = @import("verbs/start.zig");
const attach_verb = @import("verbs/attach_verb.zig");
const attach = @import("attach.zig");

const KNOWN_VERBS = [_][]const u8{
	"start", "stop",  "restart", "status",  "list",    "init",
	"ssh",   "rules", "remap",   "l7",      "console", "monitor",
	"help",
	// Hidden re-exec / helper targets, recognized below but omitted from
	// help: "__launch" (re-exec), "__l7proxy" (the host-side L7 proxy),
	// "__render-rules" (boot-time runtime-file renderer).
	"__launch", "__l7proxy", "__render-rules",
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
		if (std.mem.eql(u8, argv[0], "run")) {
			util.die(allocator, io, null, exit_codes.usage, "'run' was removed. Bare 'cogbox' now starts in the background; add -f/--foreground to attach the console.", .{});
		}
	}

	// Determine verb. If argv[0] is a known verb, that's the verb.
	// Otherwise (no args, or first arg looks like a flag), default to
	// `start` -- bare `cogbox` launches in the background.
	var verb: []const u8 = "start";
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
	if (std.mem.eql(u8, verb, "remap")) return remap_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "l7")) return l7_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "__l7proxy")) {
		if (rest.len < 1) util.die(allocator, io, null, exit_codes.usage, "__l7proxy requires a runtime dir [l7-base-port]", .{});
		// Optional L7 port base (default canonical); the launcher passes the
		// instance's allocated base so per-instance ports don't collide.
		const base: u16 = if (rest.len >= 2)
			std.fmt.parseInt(u16, rest[1], 10) catch filter_mod.l7_default_base
		else
			filter_mod.l7_default_base;
		return l7proxy_module.run(allocator, rest[0], base);
	}
	if (std.mem.eql(u8, verb, "__render-rules")) {
		if (rest.len < 2) util.die(allocator, io, null, exit_codes.usage, "__render-rules requires <config> <runtime>", .{});
		return rules_module.renderFiles(allocator, io, rest[0], rest[1]);
	}
	if (std.mem.eql(u8, verb, "console")) return attach_verb.run(allocator, io, &p, rest, attach.Target.console);
	if (std.mem.eql(u8, verb, "monitor")) return attach_verb.run(allocator, io, &p, rest, attach.Target.monitor);
	if (std.mem.eql(u8, verb, "init")) return run_verb.run(allocator, io, env, rest);
	if (std.mem.eql(u8, verb, "__launch")) return run_verb.launchInPlace(allocator, io, env, rest);
	if (std.mem.eql(u8, verb, "start")) return start_verb.run(allocator, io, env, &p, rest);

	util.die(allocator, io, null, exit_codes.usage, "unknown verb '{s}'", .{verb});
}

fn isKnownVerb(s: []const u8) bool {
	for (KNOWN_VERBS) |v| {
		if (std.mem.eql(u8, v, s)) return true;
	}
	return false;
}
