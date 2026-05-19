// Regenerate the runtime rules file (read by the LD_PRELOAD filter) and
// signal a running passt to re-read it. Emits both the CIDR allow/deny
// section AND the remap section from the loaded .network object, so the
// `rules` and `remap` verbs can each rewrite the file independently
// without dropping the other layer.

const std = @import("std");
const rule = @import("rule.zig");

/// Render `.network` to wire-format rule lines. Pure -- no I/O.
/// Ordering on disk is stable: CIDR rules first, then remap.
pub fn renderRules(allocator: std.mem.Allocator, network: std.json.Value, out: *std.ArrayList(u8)) !void {
	if (network != .object) return;

	if (network.object.getPtr("rules")) |rules_val| {
		if (rules_val.* == .array) {
			for (rules_val.array.items) |r| {
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
		}
	}

	if (network.object.getPtr("remap")) |remap_val| {
		if (remap_val.* == .array) {
			for (remap_val.array.items) |r| {
				if (r != .object) continue;
				const from_v = r.object.getPtr("from") orelse continue;
				const to_v = r.object.getPtr("to") orelse continue;
				if (from_v.* != .string or to_v.* != .string) continue;
				try out.appendSlice(allocator, "remap ");
				try out.appendSlice(allocator, from_v.string);
				try out.appendSlice(allocator, " -> ");
				try out.appendSlice(allocator, to_v.string);
				try out.append(allocator, '\n');
			}
		}
	}
}

pub fn writeRuntimeRules(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, network: std.json.Value) !void {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, "netfilter-rules" });
	defer allocator.free(path);

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	try renderRules(allocator, network, &out);

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
