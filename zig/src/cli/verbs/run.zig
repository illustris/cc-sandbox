// `cogbox init` - validate args, then exec the bash launch script in
// the foreground with --init-only. The script seeds host state and (for
// customized per-instance flakes) warms the runner build, then stops before
// runtime setup. The VM launch itself is the `start` verb's job.
//
// This module also exports `validate`, shared by the `start` verb.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const launch = @import("../launch.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "vcpu", .kind = .value },
		.{ .long = "mem", .kind = .value },
		.{ .long = "network", .kind = .value },
		.{ .long = "no-auto-keys", .kind = .bool },
		.{ .long = "yes", .short = 'y', .kind = .bool },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "init", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.INIT);
		return;
	}

	const opts = try validate(&parsed, allocator, io, "init");
	try launch.execLaunchScript(allocator, io, env, opts, true);
}

/// Hidden `__launch` verb. Exec the launch script in full-launch mode in
/// place (no fork, no interactive init). Only used by the bash script's
/// custom-flake re-exec path (`nix run ... -- __launch`), which runs inside
/// the already-daemonized process and must not fork or prompt again.
pub fn launchInPlace(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	argv: []const []const u8,
) !void {
	// Only reachable via the bash re-exec, which runs under COGBOX_REEXECED=1.
	// A hand-typed `cogbox __launch` would launch QEMU in the foreground with
	// no daemonization, so reject it as an unknown verb.
	if (env.get("COGBOX_REEXECED") == null) {
		util.die(allocator, io, null, exit_codes.usage, "unknown verb '__launch'", .{});
	}
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "vcpu", .kind = .value },
		.{ .long = "mem", .kind = .value },
		.{ .long = "network", .kind = .value },
		.{ .long = "no-auto-keys", .kind = .bool },
		.{ .long = "yes", .short = 'y', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "__launch", .flags = &flags }, argv);
	defer parsed.deinit();
	const opts = try validate(&parsed, allocator, io, "__launch");
	try launch.execLaunchScript(allocator, io, env, opts, false);
}

pub fn validate(
	parsed: *const parse.Parsed,
	allocator: std.mem.Allocator,
	io: std.Io,
	verb_name: []const u8,
) !launch.LaunchOpts {
	const name: ?[]const u8 = blk: {
		const v = parsed.get("name") orelse break :blk null;
		if (std.mem.eql(u8, v, "default")) {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(v)) {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		break :blk v;
	};

	const vcpu: ?u32 = blk: {
		const v = parsed.get("vcpu") orelse break :blk null;
		break :blk parse.parseIntRange(v, 1, 256) catch |err| switch (err) {
			error.NotInteger => util.die(allocator, io, verb_name, exit_codes.dataerr, "--vcpu must be a positive integer", .{}),
			error.OutOfRange => util.die(allocator, io, verb_name, exit_codes.dataerr, "--vcpu must be between 1 and 256", .{}),
		};
	};

	const mem: ?u32 = blk: {
		const v = parsed.get("mem") orelse break :blk null;
		break :blk parse.parseIntRange(v, 256, 1_048_576) catch |err| switch (err) {
			error.NotInteger => util.die(allocator, io, verb_name, exit_codes.dataerr, "--mem must be a positive integer (megabytes)", .{}),
			error.OutOfRange => util.die(allocator, io, verb_name, exit_codes.dataerr, "--mem must be between 256 and 1048576 megabytes", .{}),
		};
	};

	const network: ?[]const u8 = blk: {
		const v = parsed.get("network") orelse break :blk null;
		_ = parse.parseNetworkMode(v) catch {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "--network must be \"full\", \"none\", or \"rules\"", .{});
		};
		break :blk v;
	};

	return .{
		.name = name,
		.vcpu = vcpu,
		.mem = mem,
		.network = network,
		.auto_keys = !parsed.isSet("no-auto-keys"),
		.yes = parsed.isSet("yes"),
		.foreground = parsed.isSet("foreground"),
		.no_ssh = parsed.isSet("no-ssh"),
	};
}
