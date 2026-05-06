// Common helpers for verbs that exec the bash launch script.
//
// The launch script lives in $out/libexec/cogbox-launch.sh, alongside
// the binary at $out/bin/cogbox. We resolve the path at runtime via
// /proc/self/exe so the binary is relocatable (no compile-time bake).

const std = @import("std");

pub const LaunchOpts = struct {
	name: ?[]const u8,
	vcpu: ?u32,
	mem: ?u32,
	network: ?[]const u8,
	auto_keys: bool,
	yes: bool,
	init_only: bool,
};

/// Build the argv that the bash launch script expects.
/// Caller owns the returned slice and each element.
pub fn buildLaunchArgs(allocator: std.mem.Allocator, opts: LaunchOpts, script_path: []const u8) ![]const []const u8 {
	var args: std.ArrayList([]const u8) = .empty;
	errdefer args.deinit(allocator);

	try args.append(allocator, try allocator.dupe(u8, script_path));

	if (opts.name) |n| {
		try args.append(allocator, try allocator.dupe(u8, "--name"));
		try args.append(allocator, try allocator.dupe(u8, n));
	}
	if (opts.vcpu) |v| {
		try args.append(allocator, try allocator.dupe(u8, "--vcpu"));
		try args.append(allocator, try std.fmt.allocPrint(allocator, "{d}", .{v}));
	}
	if (opts.mem) |m| {
		try args.append(allocator, try allocator.dupe(u8, "--mem"));
		try args.append(allocator, try std.fmt.allocPrint(allocator, "{d}", .{m}));
	}
	if (opts.network) |n| {
		try args.append(allocator, try allocator.dupe(u8, "--network"));
		try args.append(allocator, try allocator.dupe(u8, n));
	}
	if (!opts.auto_keys) try args.append(allocator, try allocator.dupe(u8, "--no-auto-keys"));
	if (opts.yes) try args.append(allocator, try allocator.dupe(u8, "--yes"));
	if (opts.init_only) try args.append(allocator, try allocator.dupe(u8, "--init-only"));

	return try args.toOwnedSlice(allocator);
}

/// Resolve the absolute path to libexec/cogbox-launch.sh by reading
/// /proc/self/exe and walking up. Falls back to the COGBOX_LAUNCH_SCRIPT
/// env var for testing.
pub fn resolveScriptPath(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) ![]const u8 {
	if (env.get("COGBOX_LAUNCH_SCRIPT")) |p| {
		return try allocator.dupe(u8, p);
	}

	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const n = try std.Io.Dir.readLinkAbsolute(io, "/proc/self/exe", &buf);
	const exe = buf[0..n];
	// exe = .../bin/cogbox  -> bin_dir = .../bin  -> prefix = ...
	const bin_dir = std.fs.path.dirname(exe) orelse return error.NoBinDir;
	const prefix = std.fs.path.dirname(bin_dir) orelse return error.NoPrefix;
	return try std.fs.path.join(allocator, &.{ prefix, "libexec", "cogbox-launch.sh" });
}

extern "c" fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

/// Replace the current process with `argv[0]` invoked with `argv`.
pub fn execvAlloc(allocator: std.mem.Allocator, argv: []const []const u8) !void {
	const argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
	defer allocator.free(argv_z);
	for (argv, 0..) |a, i| {
		const z = try allocator.dupeZ(u8, a);
		argv_z[i] = z.ptr;
	}
	argv_z[argv.len] = null;

	const prog = try allocator.dupeZ(u8, argv[0]);
	const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
	_ = execv(prog.ptr, argv_ptr);
	return error.ExecvFailed;
}
