// `cogbox start` - daemonize the bash launch script in the background.
//
// Implementation:
//   1. Validate args (same as run)
//   2. Check $RUNTIME/pid; if alive, exit 75
//   3. fork(). Parent: poll $RUNTIME/ssh-endpoint up to 30s, return.
//      Child: setsid, dup stdout/stderr to $RUNTIME/cogbox.log,
//      execve cogbox-launch.sh.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const launch = @import("../launch.zig");
const run_verb = @import("run.zig");

extern "c" fn fork() c_int;
extern "c" fn setsid() c_int;
extern "c" fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn _exit(code: c_int) noreturn;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_RDONLY: c_int = 0;

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	p: *const paths.Paths,
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
	var parsed = parse.parse(allocator, io, .{ .verb = "start", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.START);
		return;
	}

	const opts = try run_verb.validate(&parsed, allocator, io, "start", false);

	// Already-running check.
	const inst_runtime = try paths.instanceRuntime(allocator, p, opts.name);
	defer allocator.free(inst_runtime);
	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);
	if (isRunning(allocator, io, pid_path)) {
		util.die(allocator, io, "start", exit_codes.tempfail, "instance is already running. Use 'cogbox stop' first or 'cogbox restart'.", .{});
	}

	const script_path = try launch.resolveScriptPath(allocator, io, env);
	defer allocator.free(script_path);

	const script_argv = try launch.buildLaunchArgs(allocator, opts, script_path);
	defer {
		for (script_argv) |a| allocator.free(a);
		allocator.free(script_argv);
	}

	// Ensure runtime dir exists for the log redirection.
	std.Io.Dir.cwd().createDirPath(io, inst_runtime) catch {};
	const log_path = try std.fs.path.join(allocator, &.{ inst_runtime, "cogbox.log" });
	defer allocator.free(log_path);

	const pid = fork();
	if (pid < 0) {
		util.die(allocator, io, "start", exit_codes.software, "fork failed", .{});
	}

	if (pid == 0) {
		// Child: detach. Note that the bash launch script writes its own
		// pid to <runtime>/pid using `$$`, which after setsid is the new
		// session leader -- exactly what we want for the stop verb to
		// signal.
		_ = setsid();

		// Redirect stdin -> /dev/null, stdout/stderr -> log file.
		const log_z = allocator.dupeZ(u8, log_path) catch _exit(70);
		const devnull_z = allocator.dupeZ(u8, "/dev/null") catch _exit(70);
		const fd_in = open(devnull_z.ptr, O_RDONLY, 0);
		if (fd_in >= 0) {
			_ = dup2(fd_in, 0);
			_ = close(fd_in);
		}
		const fd_log = open(log_z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
		if (fd_log >= 0) {
			_ = dup2(fd_log, 1);
			_ = dup2(fd_log, 2);
			_ = close(fd_log);
		}

		// execv into bash launch script
		const argv_z = allocator.alloc(?[*:0]const u8, script_argv.len + 1) catch _exit(70);
		for (script_argv, 0..) |a, i| {
			argv_z[i] = (allocator.dupeZ(u8, a) catch _exit(70)).ptr;
		}
		argv_z[script_argv.len] = null;
		const prog_z = allocator.dupeZ(u8, script_argv[0]) catch _exit(70);
		const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
		_ = execv(prog_z.ptr, argv_ptr);
		_exit(70);
	}

	// Parent: poll for ssh-endpoint or daemon death.
	const endpoint_path = try std.fs.path.join(allocator, &.{ inst_runtime, "ssh-endpoint" });
	defer allocator.free(endpoint_path);
	const cwd = std.Io.Dir.cwd();
	const max_wait_ms: i64 = 30_000;
	const step_ms: i64 = 200;
	var waited: i64 = 0;
	while (waited < max_wait_ms) : (waited += step_ms) {
		_ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
		// Daemon died?
		const sig_zero: std.posix.SIG = @enumFromInt(0);
		if (std.posix.kill(pid, sig_zero)) |_| {
			// alive; check endpoint
			cwd.access(io, endpoint_path, .{}) catch continue;
			try util.say(allocator, io, "Started instance{s}{s}. Logs: {s}", .{
				if (opts.name != null) " " else "",
				opts.name orelse "",
				log_path,
			});
			return;
		} else |_| {
			util.die(allocator, io, "start", exit_codes.software, "daemon exited before SSH came up. See {s} for details.", .{log_path});
		}
	}

	util.die(allocator, io, "start", exit_codes.software, "timed out waiting for SSH endpoint at {s}. See {s} for details.", .{ endpoint_path, log_path });
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
