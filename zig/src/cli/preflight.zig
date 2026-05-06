// Pre-verb checks: legacy cc-sandbox -> cogbox migration warnings/errors,
// and stale-runtime-dir hints.
//
// These run before every verb (not just launch) so that someone running
// `cogbox list` after the rename also gets the migration prompt.
// Mirrors cogbox.sh:217-238.

const std = @import("std");
const util = @import("util.zig");
const exit_codes = @import("exit.zig");
const paths = @import("paths.zig");

const LEGACY_VARS = [_][]const u8{
	"CC_SANDBOX_DATA",
	"CC_SANDBOX_CLAUDE_CONFIG",
	"CC_SANDBOX_CLAUDE_AUTH",
	"CC_SANDBOX_OPENCODE_CONFIG",
	"CC_SANDBOX_OPENCODE_DATA",
};

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	p: *const paths.Paths,
) !void {
	// Stale env vars: warn but don't fail. Their replacements have the same
	// semantics with the COGBOX_ prefix.
	for (LEGACY_VARS) |v| {
		if (env.get(v) != null) {
			const new_name = try std.fmt.allocPrint(allocator, "COGBOX_{s}", .{v[11..]});
			defer allocator.free(new_name);
			try util.warn(allocator, io, "{s} is set but no longer honored. Rename to {s}.", .{ v, new_name });
		}
	}

	// Legacy on-disk dirs: hard-fail with a migration hint. We don't
	// silently mutate the user's filesystem.
	const home = p.real_home;
	const xdg_config = env.get("XDG_CONFIG_HOME");
	const xdg_data = env.get("XDG_DATA_HOME");

	const legacy_config = if (xdg_config) |c|
		try std.fs.path.join(allocator, &.{ c, "cc-sandbox" })
	else
		try std.fs.path.join(allocator, &.{ home, ".config", "cc-sandbox" });
	defer allocator.free(legacy_config);

	const legacy_data = if (xdg_data) |d|
		try std.fs.path.join(allocator, &.{ d, "cc-sandbox" })
	else
		try std.fs.path.join(allocator, &.{ home, ".local", "share", "cc-sandbox" });
	defer allocator.free(legacy_data);

	const cwd = std.Io.Dir.cwd();
	if (existsDir(io, cwd, legacy_config) and !existsAny(io, cwd, p.config_dir)) {
		try util.writeStderr(io, "cogbox: error: cc-sandbox was renamed to cogbox. Move your config:\n");
		const hint = try std.fmt.allocPrint(allocator, "  mv '{s}' '{s}'\n", .{ legacy_config, p.config_dir });
		defer allocator.free(hint);
		try util.writeStderr(io, hint);
		std.process.exit(exit_codes.software);
	}
	if (existsDir(io, cwd, legacy_data) and !existsAny(io, cwd, p.base_data)) {
		try util.writeStderr(io, "cogbox: error: cc-sandbox was renamed to cogbox. Move your data:\n");
		const hint = try std.fmt.allocPrint(allocator, "  mv '{s}' '{s}'\n", .{ legacy_data, p.base_data });
		defer allocator.free(hint);
		try util.writeStderr(io, hint);
		std.process.exit(exit_codes.software);
	}
}

fn existsDir(io: std.Io, dir: std.Io.Dir, p: []const u8) bool {
	dir.access(io, p, .{}) catch return false;
	return true;
}

fn existsAny(io: std.Io, dir: std.Io.Dir, p: []const u8) bool {
	dir.access(io, p, .{}) catch return false;
	return true;
}
