// Regenerate the runtime rules file (read by the LD_PRELOAD filter) and
// signal a running passt to re-read it. Mirrors the shell behavior at
// cc-sandbox.sh:264-271.

const std = @import("std");
const rule = @import("rule.zig");

pub fn writeRuntimeRules(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, rules_arr: std.json.Array) !void {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, "netfilter-rules" });
	defer allocator.free(path);

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	for (rules_arr.items) |r| {
		if (r != .object) continue;
		const p = rule.ruleAction(r.object) orelse continue;
		const action_str = switch (p.action) {
			.allow => "allow",
			.deny => "deny",
		};
		try out.appendSlice(allocator, action_str);
		try out.append(allocator, ' ');
		try out.appendSlice(allocator, p.cidr);
		try out.append(allocator, '\n');
	}

	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var write_buf: [4096]u8 = undefined;
	var writer = f.writer(io, &write_buf);
	try writer.interface.writeAll(out.items);
	try writer.flush();
}

/// If <runtime>/passt.pid exists and the process is alive, send SIGUSR1.
/// Returns true if a signal was sent.
pub fn maybeSignalPasst(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8) !bool {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, "passt.pid" });
	defer allocator.free(path);

	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, path, .{}) catch |err| switch (err) {
		error.FileNotFound => return false,
		else => return err,
	};
	defer file.close(io);

	var read_buf: [64]u8 = undefined;
	var reader = file.reader(io, &read_buf);
	const contents = reader.interface.allocRemaining(allocator, .limited(64)) catch return false;
	defer allocator.free(contents);

	const trimmed = std.mem.trim(u8, contents, " \t\r\n");
	const pid = std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return false;

	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	std.posix.kill(pid, std.posix.SIG.USR1) catch return false;
	return true;
}
