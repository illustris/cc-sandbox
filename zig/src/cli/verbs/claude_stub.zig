// Hidden helper: `cogbox __claude-stub <claude-dir> <marker>`.
//
// Reconcile the redacted in-guest Claude credential against a per-instance MARKER
// file, so claude-code on the CONTAINER backend boots "logged-in but tokenless"
// exactly when -- and only when -- the sandbox owner has connected their Claude
// account (the step-5b container stub-staging).
//
// The signal is one marker file on the state PVC that cogworx's reconcile sets
// when it binds the owner's `claude-oauth` setup-token into the enforcer (and
// clears on disconnect). This verb makes <claude-dir>/.credentials.json match it:
//
//   marker PRESENT -> write the redacted stub (accessToken = the shared sentinel;
//     the enforcer's mitm addon stamps the real Bearer ONLY over it). The real
//     token never enters the agent -- only the inert stub is ever written here.
//   marker ABSENT  -> remove the stub so claude-code falls back to in-guest
//     /login (fail-closed, today's behavior, S5).
//
// It is invoked at boot (a oneshot, for restart persistence -- the marker + the
// stub both live on the state PVC) and on connect/disconnect (cogworx sets/clears
// the marker then restarts that oneshot), so both paths share one renderer. The
// home-dir symlinks that point ~/.claude at the PVC are wired by the oneshot's
// shell; this verb owns only the marker-gated, token-bearing write/remove.

const std = @import("std");
const util = @import("../util.zig");
const exit_codes = @import("../exit.zig");
const secret_mod = @import("secret_module");

pub fn run(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
	if (argv.len < 2) {
		util.die(allocator, io, "__claude-stub", exit_codes.usage, "__claude-stub requires <claude-dir> <marker>", .{});
	}
	reconcile(allocator, io, argv[0], argv[1]) catch |err| {
		util.die(allocator, io, "__claude-stub", exit_codes.software, "failed to reconcile the Claude stub: {s}", .{@errorName(err)});
	};
}

/// Make `<claude_dir>/.credentials.json` match the marker: stage the redacted
/// stub when `marker` exists, else remove it. Idempotent (a boot oneshot + a
/// connect/disconnect trigger both call it), so a re-run with the marker present
/// leaves the stub in place -- the basis for restart persistence. Pure of the
/// real token: the only value it ever writes is the shared sentinel stub.
pub fn reconcile(allocator: std.mem.Allocator, io: std.Io, claude_dir: []const u8, marker: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const cred_path = try std.fs.path.join(allocator, &.{ claude_dir, ".credentials.json" });
	defer allocator.free(cred_path);

	const connected = blk: {
		cwd.access(io, marker, .{}) catch break :blk false;
		break :blk true;
	};

	if (connected) {
		// ~/.claude must exist before the cred file lands in it (the oneshot
		// symlinks ~/.claude at this PVC dir; createDirPath is a no-op when present).
		try cwd.createDirPath(io, claude_dir);
		const json = try secret_mod.stubCredentialJson(allocator);
		defer allocator.free(json);
		try writeFile0600(io, cred_path, json);
	} else {
		// Disconnected / never-connected: drop the stub so claude-code hits /login.
		cwd.deleteFile(io, cred_path) catch {};
	}
}

/// Write `bytes` to `path` truncating, mode 0600 (the credential file mirrors the
/// store's 0600 custody; the in-guest stub is inert but kept owner-only anyway).
fn writeFile0600(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{ .truncate = true, .permissions = std.Io.File.Permissions.fromMode(0o600) });
	defer f.close(io);
	var wbuf: [512]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

// --- tests -----------------------------------------------------------------

// A self-made claude dir + marker dir (relative to cwd) for the IO tests; the
// caller owns teardown. Returns the dir name allocated in `gpa`.
fn tmpDir(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-claudestub-test-{s}", .{hexb});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

fn credExists(io: std.Io, claude_dir: []const u8) bool {
	const cwd = std.Io.Dir.cwd();
	var buf: [512]u8 = undefined;
	const p = std.fmt.bufPrint(&buf, "{s}/.credentials.json", .{claude_dir}) catch return false;
	cwd.access(io, p, .{}) catch return false;
	return true;
}

fn readCred(gpa: std.mem.Allocator, io: std.Io, claude_dir: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const p = try std.fmt.allocPrint(gpa, "{s}/.credentials.json", .{claude_dir});
	defer gpa.free(p);
	const f = try cwd.openFile(io, p, .{});
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(gpa, .limited(1 << 20));
}

test "claude stub: staged iff the marker is present, removed when absent" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpDir(gpa, io);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};

	const claude_dir = try std.fmt.allocPrint(gpa, "{s}/.claude", .{root});
	defer gpa.free(claude_dir);
	const marker = try std.fmt.allocPrint(gpa, "{s}/claude-oauth.bound", .{root});
	defer gpa.free(marker);

	// Not connected (no marker) -> NO stub (fail-closed, /login fallback).
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(!credExists(io, claude_dir));

	// Connect: cogworx sets the marker. Reconcile -> the stub appears, and it
	// carries ONLY the shared sentinel (no real token ever enters the agent).
	{
		const f = try cwd.createFile(io, marker, .{ .truncate = true });
		f.close(io);
	}
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expect(std.mem.indexOf(u8, cred, secret_mod.claude_stub_token) != null);
		try std.testing.expect(std.mem.indexOf(u8, cred, "sk-ant-oat01-FAKE") == null);
	}

	// Disconnect: cogworx clears the marker. Reconcile -> the stub is removed.
	try cwd.deleteFile(io, marker);
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(!credExists(io, claude_dir));
}

test "claude stub: survives a simulated restart (marker persists -> re-staged)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpDir(gpa, io);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};

	const claude_dir = try std.fmt.allocPrint(gpa, "{s}/.claude", .{root});
	defer gpa.free(claude_dir);
	const marker = try std.fmt.allocPrint(gpa, "{s}/claude-oauth.bound", .{root});
	defer gpa.free(marker);

	// Connected, staged once.
	{
		const f = try cwd.createFile(io, marker, .{ .truncate = true });
		f.close(io);
	}
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));

	// "Restart": the marker + claude dir live on the state PVC, so they survive. The
	// boot oneshot re-runs the SAME reconcile -> the stub is (still) present, and the
	// re-run is idempotent (no error overwriting it).
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));
}
