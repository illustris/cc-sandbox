// `cogbox status` - report whether a single instance is running.
// Exit codes: 0 running, 3 stopped, 64 unknown instance.

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
	var parsed = parse.parse(allocator, io, .{ .verb = "status", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.STATUS);
		return;
	}

	const name = nameFlag(&parsed, allocator, io);

	const inst_cfg = try paths.instanceConfigDir(allocator, p, name);
	defer allocator.free(inst_cfg);
	const cfg_path = try std.fs.path.join(allocator, &.{ inst_cfg, "config.json" });
	defer allocator.free(cfg_path);
	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const cwd = std.Io.Dir.cwd();
	cwd.access(io, cfg_path, .{}) catch {
		const eff = name orelse "default";
		util.die(allocator, io, "status", exit_codes.usage, "no such instance: \"{s}\"", .{eff});
	};

	// Try to read pid + check liveness.
	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);

	const pid = readPid(allocator, io, pid_path) catch null;
	const alive = if (pid) |p_| livenessCheck(p_) else false;

	if (!alive) {
		try util.writeStdout(io, "stopped\n");
		std.process.exit(exit_codes.status_stopped);
	}

	const endpoint_path = try std.fs.path.join(allocator, &.{ inst_runtime, "ssh-endpoint" });
	defer allocator.free(endpoint_path);
	var ssh_host: []const u8 = "?";
	var ssh_port: []const u8 = "?";
	var endpoint_text: ?[]u8 = null;
	defer if (endpoint_text) |t| allocator.free(t);
	if (readSmall(allocator, io, endpoint_path)) |text| {
		endpoint_text = text;
		var iter = std.mem.tokenizeAny(u8, text, " \t\r\n");
		if (iter.next()) |port| ssh_port = port;
		if (iter.next()) |host| ssh_host = host;
	} else |_| {}

	const cfg_text = try readSmall(allocator, io, cfg_path);
	defer allocator.free(cfg_text);
	const parsed_cfg = std.json.parseFromSlice(std.json.Value, allocator, cfg_text, .{}) catch
		util.die(allocator, io, "status", exit_codes.software, "invalid JSON in {s}", .{cfg_path});
	defer parsed_cfg.deinit();

	const obj = if (parsed_cfg.value == .object) parsed_cfg.value.object else
		util.die(allocator, io, "status", exit_codes.software, "config is not an object: {s}", .{cfg_path});
	const http_port: i64 = blk: {
		const v = obj.get("httpPort") orelse break :blk 8080;
		break :blk if (v == .integer) v.integer else 8080;
	};
	const bind_addr: []const u8 = blk: {
		const v = obj.get("bindAddr") orelse break :blk "127.0.0.1";
		break :blk if (v == .string) v.string else "127.0.0.1";
	};

	const net_label = networkLabel(obj);

	try util.say(allocator, io,
		"running pid={d} ssh={s}:{s} http={s}:{d} net={s}",
		.{ pid.?, if (ssh_host.len > 0) ssh_host else bind_addr, ssh_port, bind_addr, http_port, net_label },
	);
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "status", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "status", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

fn readPid(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.posix.pid_t {
	const text = try readSmall(allocator, io, path);
	defer allocator.free(text);
	const trimmed = std.mem.trim(u8, text, " \t\r\n");
	return std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return error.InvalidPid;
}

fn livenessCheck(pid: std.posix.pid_t) bool {
	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	return true;
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const file = try cwd.openFile(io, path, .{});
	defer file.close(io);
	var buf: [4096]u8 = undefined;
	var reader = file.reader(io, &buf);
	return try reader.interface.allocRemaining(allocator, .limited(1 << 20));
}

fn networkLabel(obj: std.json.ObjectMap) []const u8 {
	const v = obj.get("network") orelse return "full";
	switch (v) {
		.string => |s| {
			if (std.mem.eql(u8, s, "full")) return "full";
			if (std.mem.eql(u8, s, "none")) return "none";
			return "rules";
		},
		else => return "rules",
	}
}
