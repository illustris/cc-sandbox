// `cogbox run` - validate args, then exec the bash launch script in
// the foreground. The bash script handles init/migration/launch.

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
	verb_name: []const u8, // "run" for help text on errors
	init_only: bool, // true when invoked as `cogbox init`
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
	var parsed = parse.parse(allocator, io, .{ .verb = verb_name, .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, if (init_only) help.INIT else help.RUN);
		return;
	}

	const opts = try validate(&parsed, allocator, io, verb_name, init_only);

	const script_path = try launch.resolveScriptPath(allocator, io, env);
	defer allocator.free(script_path);

	const script_argv = try launch.buildLaunchArgs(allocator, opts, script_path);
	defer {
		for (script_argv) |a| allocator.free(a);
		allocator.free(script_argv);
	}

	try launch.execvAlloc(allocator, script_argv);
}

pub fn validate(
	parsed: *const parse.Parsed,
	allocator: std.mem.Allocator,
	io: std.Io,
	verb_name: []const u8,
	init_only: bool,
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
		.init_only = init_only,
	};
}
