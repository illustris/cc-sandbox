// `cogbox start` - the default launch verb (bare `cogbox` dispatches here).
//
// Always launches the VM as a background daemon. With -f/--foreground it
// then attaches the serial console; detaching (Ctrl-]) leaves the VM
// running. Without -f it prints how to attach and returns.
//
// Flow:
//   1. Validate args (shares run.zig::validate).
//   2. Refuse if an instance with this name is already running.
//   3. Run the launch script with --init-only in the FOREGROUND so first-run
//      prompts (harness selection, path creation) are interactive and any
//      custom-flake runner build happens where the user can see it.
//   4. fork(). Child: setsid, redirect stdio to <runtime>/cogbox.log, exec
//      the launch script in full-launch mode (passt + QEMU). QEMU's serial
//      console and HMP monitor are on <runtime>/{console,monitor}.sock.
//   5. Parent: wait for <runtime>/console.sock (proof QEMU launched) or
//      daemon death. Then attach the console (-f) or print + return.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const launch = @import("../launch.zig");
const attach = @import("../attach.zig");
const run_verb = @import("run.zig");

extern "c" fn fork() c_int;
extern "c" fn setsid() c_int;
extern "c" fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
extern "c" fn _exit(code: c_int) noreturn;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_RDONLY: c_int = 0;
const WNOHANG: c_int = 1;

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
		.{ .long = "foreground", .short = 'f', .kind = .bool },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "start", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.START);
		return;
	}

	const opts = try run_verb.validate(&parsed, allocator, io, "start");

	const inst_runtime = try paths.instanceRuntime(allocator, p, opts.name);
	defer allocator.free(inst_runtime);
	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);
	if (isRunning(allocator, io, pid_path)) {
		util.die(allocator, io, "start", exit_codes.tempfail, "instance is already running. Use 'cogbox stop' first, 'cogbox restart', or attach with 'cogbox console'.", .{});
	}

	const script_path = try launch.resolveScriptPath(allocator, io, env);
	defer allocator.free(script_path);

	// Step 1: foreground, interactive init. Seeds first-run state and warms
	// any custom-flake build. Exits non-zero if the user aborts.
	{
		const init_argv = try launch.buildLaunchArgs(allocator, opts, script_path, true);
		defer {
			for (init_argv) |a| allocator.free(a);
			allocator.free(init_argv);
		}
		const code = forkExecWait(allocator, init_argv);
		if (code != 0) std.process.exit(code);
	}

	// Step 2: daemonize the actual launch.
	const launch_argv = try launch.buildLaunchArgs(allocator, opts, script_path, false);
	defer {
		for (launch_argv) |a| allocator.free(a);
		allocator.free(launch_argv);
	}

	std.Io.Dir.cwd().createDirPath(io, inst_runtime) catch {};
	const log_path = try std.fs.path.join(allocator, &.{ inst_runtime, "cogbox.log" });
	defer allocator.free(log_path);

	const pid = fork();
	if (pid < 0) {
		util.die(allocator, io, "start", exit_codes.software, "fork failed", .{});
	}

	if (pid == 0) {
		// Child: detach into its own session. The bash script writes its own
		// pid (after re-exec, the post-re-exec bash) to <runtime>/pid, which
		// is what `cogbox stop` signals.
		_ = setsid();

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

		const argv_z = allocator.alloc(?[*:0]const u8, launch_argv.len + 1) catch _exit(70);
		for (launch_argv, 0..) |a, i| {
			argv_z[i] = (allocator.dupeZ(u8, a) catch _exit(70)).ptr;
		}
		argv_z[launch_argv.len] = null;
		const prog_z = allocator.dupeZ(u8, launch_argv[0]) catch _exit(70);
		const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
		_ = execv(prog_z.ptr, argv_ptr);
		_exit(70);
	}

	// Parent: wait for the VM to come up (qemu.pid, written the instant QEMU
	// is launched) or the daemon to die. qemu.pid is independent of the serial
	// console rewrite, so a console-less VM still registers as up.
	const qemu_pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "qemu.pid" });
	defer allocator.free(qemu_pid_path);
	const console_sock = try std.fs.path.join(allocator, &.{ inst_runtime, "console.sock" });
	defer allocator.free(console_sock);

	const cwd = std.Io.Dir.cwd();
	if (!waitForFileOrDeath(io, pid, cwd, qemu_pid_path, 60_000)) {
		util.die(allocator, io, "start", exit_codes.software, "VM did not come up. See {s} for details.", .{log_path});
	}

	if (opts.foreground) {
		// console.sock can lag qemu.pid by a moment; poll briefly. If the
		// instance has no serial console at all, report rather than hang.
		if (!waitForFileOrDeath(io, pid, cwd, console_sock, 15_000)) {
			util.die(allocator, io, "start", exit_codes.software, "serial console did not become available (the VM is running; check {s}).", .{log_path});
		}
		const console_log = try std.fs.path.join(allocator, &.{ inst_runtime, "console.log" });
		defer allocator.free(console_log);
		attach.attach(allocator, io, .console, console_sock, opts.name orelse "default", console_log) catch |err| {
			util.die(allocator, io, "start", exit_codes.software, "could not attach console: {s} (VM is running; try 'cogbox console')", .{@errorName(err)});
		};
		return;
	}

	const label = opts.name orelse "default";
	const name_arg: []const u8 = if (opts.name) |n|
		try std.fmt.allocPrint(allocator, " -n {s}", .{n})
	else
		try allocator.dupe(u8, "");
	defer allocator.free(name_arg);
	try util.say(allocator, io,
		"Started '{s}' in the background.\n  console: cogbox console{s}\n  monitor: cogbox monitor{s}\n  logs:    {s}",
		.{ label, name_arg, name_arg, log_path },
	);
}

/// fork + execv(argv) inheriting this process's stdio (terminal), then
/// waitpid. Returns the child's exit code (or 70 on fork/exec failure).
fn forkExecWait(allocator: std.mem.Allocator, argv: []const []const u8) u8 {
	const pid = fork();
	if (pid < 0) return 70;
	if (pid == 0) {
		const argv_z = allocator.alloc(?[*:0]const u8, argv.len + 1) catch _exit(70);
		for (argv, 0..) |a, i| {
			argv_z[i] = (allocator.dupeZ(u8, a) catch _exit(70)).ptr;
		}
		argv_z[argv.len] = null;
		const prog_z = allocator.dupeZ(u8, argv[0]) catch _exit(70);
		const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
		_ = execv(prog_z.ptr, argv_ptr);
		_exit(70);
	}
	var status: c_int = 0;
	while (true) {
		const r = waitpid(pid, &status, 0);
		if (r == pid) break;
		if (r < 0) return 70;
	}
	// WIFEXITED && WEXITSTATUS
	if (status & 0x7f == 0) return @intCast((status >> 8) & 0xff);
	return 70; // killed by signal
}

/// Poll for `path` to appear, returning true when it does. Returns false if
/// the daemon `pid` exits first (reaped via WNOHANG, so it never lingers as a
/// zombie that kill(pid,0) would misreport as alive) or the timeout elapses.
fn waitForFileOrDeath(io: std.Io, pid: c_int, cwd: std.Io.Dir, path: []const u8, max_wait_ms: i64) bool {
	const step_ms: i64 = 200;
	var waited: i64 = 0;
	while (waited < max_wait_ms) : (waited += step_ms) {
		_ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
		var status: c_int = 0;
		if (waitpid(pid, &status, WNOHANG) == pid) return false; // daemon exited
		cwd.access(io, path, .{}) catch continue;
		return true;
	}
	return false;
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
