// `cogbox stop` - send SIGTERM, wait, optionally SIGKILL.

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
		.{ .long = "force", .kind = .bool },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "stop", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.STOP);
		return;
	}

	const name = nameFlag(&parsed, allocator, io);
	const force = parsed.isSet("force");

	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);
	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);

	const pid = readPid(allocator, io, pid_path) catch {
		// No pid file or unreadable: not running. Idempotent (exit 0), but
		// report it so `stop` on a stopped instance isn't a silent no-op.
		try reportNotRunning(allocator, io, name);
		return;
	};
	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch {
		// Stale pid file (process already gone): same -- report, exit 0.
		try reportNotRunning(allocator, io, name);
		return;
	};

	std.posix.kill(pid, std.posix.SIG.TERM) catch |err| {
		util.die(allocator, io, "stop", exit_codes.software, "kill SIGTERM pid {d}: {s}", .{ pid, @errorName(err) });
	};

	const max_wait_ms: i64 = 10_000;
	const step_ms: i64 = 100;
	var waited: i64 = 0;
	while (waited < max_wait_ms) : (waited += step_ms) {
		_ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
		std.posix.kill(pid, sig_zero) catch return; // process gone
	}

	if (force) {
		std.posix.kill(pid, std.posix.SIG.KILL) catch {};
		// give the kernel a moment, then return regardless
		_ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
		return;
	}

	util.die(allocator, io, "stop", exit_codes.software, "process pid {d} did not exit within 10s. Pass --force to send SIGKILL.", .{pid});
}

fn reportNotRunning(allocator: std.mem.Allocator, io: std.Io, name: ?[]const u8) !void {
	const disp = name orelse "default";
	const msg = try std.fmt.allocPrint(allocator, "instance '{s}' is not running\n", .{disp});
	defer allocator.free(msg);
	try util.writeStdout(io, msg);
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "stop", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "stop", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

fn readPid(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.posix.pid_t {
	const cwd = std.Io.Dir.cwd();
	const file = try cwd.openFile(io, path, .{});
	defer file.close(io);
	var buf: [64]u8 = undefined;
	var reader = file.reader(io, &buf);
	const data = try reader.interface.allocRemaining(allocator, .limited(64));
	defer allocator.free(data);
	const trimmed = std.mem.trim(u8, data, " \t\r\n");
	return std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return error.InvalidPid;
}
