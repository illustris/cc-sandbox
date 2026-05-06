// `cogbox ssh` - connect to a running instance via SSH.
//
// Reads the live host:port from <runtime>/ssh-endpoint (written by the
// launch script when the VM comes up). Disables host-key checking
// because the guest's root disk is ephemeral and host keys regenerate
// on every boot.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{
		.verb = "ssh",
		.flags = &flags,
		.allow_trailing = true,
		.terminate_on_positional = true,
	}, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.SSH);
		return;
	}

	const name = nameFlag(&parsed, allocator, io);

	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);
	if (!isRunning(allocator, io, pid_path)) {
		const eff = name orelse "default";
		const hint_name: []const u8 = if (name) |n|
			try std.fmt.allocPrint(allocator, " --name {s}", .{n})
		else
			try allocator.dupe(u8, "");
		defer allocator.free(hint_name);
		try util.writeStderr(io,
			try std.fmt.allocPrint(allocator,
				"cogbox ssh: error: instance \"{s}\" is not running.\nStart it with: cogbox start{s}\n",
				.{ eff, hint_name },
			),
		);
		std.process.exit(exit_codes.software);
	}

	const endpoint_path = try std.fs.path.join(allocator, &.{ inst_runtime, "ssh-endpoint" });
	defer allocator.free(endpoint_path);
	const text = readSmall(allocator, io, endpoint_path) catch {
		util.die(allocator, io, "ssh", exit_codes.software, "missing {s} (instance launched by an older cogbox?). Restart the instance to repopulate it.", .{endpoint_path});
	};
	defer allocator.free(text);

	var iter = std.mem.tokenizeAny(u8, text, " \t\r\n");
	const port = iter.next() orelse util.die(allocator, io, "ssh", exit_codes.software, "ssh-endpoint is empty: {s}", .{endpoint_path});
	const host = iter.next() orelse util.die(allocator, io, "ssh", exit_codes.software, "ssh-endpoint missing host: {s}", .{endpoint_path});

	// Build the ssh argv: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	//                       -o LogLevel=ERROR -p <port> root@<host> [trailing...]
	const target = try std.fmt.allocPrint(allocator, "root@{s}", .{host});
	defer allocator.free(target);

	var ssh_argv: std.ArrayList([]const u8) = .empty;
	defer ssh_argv.deinit(allocator);
	try ssh_argv.append(allocator, "ssh");
	try ssh_argv.append(allocator, "-o");
	try ssh_argv.append(allocator, "StrictHostKeyChecking=no");
	try ssh_argv.append(allocator, "-o");
	try ssh_argv.append(allocator, "UserKnownHostsFile=/dev/null");
	try ssh_argv.append(allocator, "-o");
	try ssh_argv.append(allocator, "LogLevel=ERROR");
	try ssh_argv.append(allocator, "-p");
	try ssh_argv.append(allocator, port);
	try ssh_argv.append(allocator, target);
	for (parsed.trailing.items) |t| try ssh_argv.append(allocator, t);
	for (parsed.positional.items) |t| try ssh_argv.append(allocator, t);

	try execvpAlloc(allocator, ssh_argv.items);
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "ssh", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "ssh", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const file = try cwd.openFile(io, path, .{});
	defer file.close(io);
	var buf: [256]u8 = undefined;
	var reader = file.reader(io, &buf);
	return try reader.interface.allocRemaining(allocator, .limited(4096));
}

fn isRunning(allocator: std.mem.Allocator, io: std.Io, pid_path: []const u8) bool {
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, pid_path, .{}) catch return false;
	defer file.close(io);
	var buf: [64]u8 = undefined;
	var reader = file.reader(io, &buf);
	const data = reader.interface.allocRemaining(allocator, .limited(64)) catch return false;
	defer allocator.free(data);
	const trimmed = std.mem.trim(u8, data, " \t\r\n");
	const pid = std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return false;
	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	return true;
}

extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

/// execvp via libc: replaces the current process. Allocates null-terminated
/// strings for the argv array.
pub fn execvpAlloc(allocator: std.mem.Allocator, argv: []const []const u8) !void {
	const argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
	defer allocator.free(argv_z);
	for (argv, 0..) |a, i| {
		const z = try allocator.dupeZ(u8, a);
		argv_z[i] = z.ptr;
	}
	argv_z[argv.len] = null;

	const prog = try allocator.dupeZ(u8, argv[0]);
	const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
	_ = execvp(prog.ptr, argv_ptr);
	// If execvp returns, it failed.
	return error.ExecvpFailed;
}
