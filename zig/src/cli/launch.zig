// Common helpers for verbs that exec the bash launch script.
//
// The launch script lives in $out/libexec/cogbox-launch.sh, alongside
// the binary at $out/bin/cogbox. We resolve the path at runtime via
// /proc/self/exe so the binary is relocatable (no compile-time bake).
//
// Launch modes (passed to the script):
//   --init-only   seed host state + (for custom flakes) warm the runner
//                 build via re-exec, then stop before runtime setup. Used
//                 by `cogbox init` and by the foreground init step of the
//                 default launch.
//   (no flag)     full launch: runtime setup + passt + QEMU. The script
//                 daemonization itself is driven by the Zig `start` verb,
//                 which forks before exec'ing the script in this mode.

const std = @import("std");

pub const LaunchOpts = struct {
	name: ?[]const u8,
	vcpu: ?u32,
	mem: ?u32,
	network: ?[]const u8,
	auto_keys: bool,
	yes: bool,
	/// Zig-side only (never forwarded to the bash script): attach the serial
	/// console after the VM comes up instead of returning immediately.
	foreground: bool,
	/// Zig-side only: suppress the default auto-ssh. With neither this nor
	/// `foreground`, `start` waits for the guest's sshd and then execs `ssh`;
	/// with this set it just prints how to connect and returns.
	no_ssh: bool,
};

/// Build the argv that the bash launch script expects. `init_only` selects
/// the script mode; `opts.foreground` is intentionally NOT forwarded (it is
/// handled entirely on the Zig side).
/// Caller owns the returned slice and each element.
pub fn buildLaunchArgs(
	allocator: std.mem.Allocator,
	opts: LaunchOpts,
	script_path: []const u8,
	init_only: bool,
) ![]const []const u8 {
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
	if (init_only) try args.append(allocator, try allocator.dupe(u8, "--init-only"));

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

/// Resolve the script path, build args for `init_only`, and exec it in place
/// (replacing this process). Used by `cogbox init` (init_only=true,
/// foreground) and the hidden `__launch` re-exec target (init_only=false).
pub fn execLaunchScript(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	opts: LaunchOpts,
	init_only: bool,
) !void {
	const script_path = try resolveScriptPath(allocator, io, env);
	const argv = try buildLaunchArgs(allocator, opts, script_path, init_only);
	try execvAlloc(allocator, argv);
}
