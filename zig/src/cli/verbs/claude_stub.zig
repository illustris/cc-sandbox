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
//   marker PRESENT and not "0" -> write the redacted stub (accessToken = the
//     shared sentinel; the enforcer's mitm addon stamps the real Bearer ONLY
//     over it). The real token never enters the agent -- only the inert stub is
//     ever written here.
//   marker "0" (the VM-family backends' explicit "not bound") or ABSENT (the
//     container clears the marker instead) -> remove the stub, but ONLY when the
//     file carries our own sentinel. A credential the sandbox user placed with
//     an in-guest /login lands at this exact path and is THEIRS: it must survive.
//
// Removing the stub is UX, not denial: what makes a disconnected owner's traffic
// fail closed is host-side -- cogworx unbinds the enforcer secret, and the
// enforcer's render gate (rules/reload.zig claudeOAuthBound) then emits no
// inject spec and no funnel at all. No guest file is an input to that decision,
// which is why preserving one weakens nothing.
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
/// stub when `marker` says bound, else remove OUR OWN stub. Idempotent (a boot
/// oneshot + a connect/disconnect trigger both call it), so a re-run with the
/// marker present leaves the stub in place -- the basis for restart persistence.
/// Pure of the real token: the only value it ever writes is the shared sentinel
/// stub.
pub fn reconcile(allocator: std.mem.Allocator, io: std.Io, claude_dir: []const u8, marker: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const cred_path = try std.fs.path.join(allocator, &.{ claude_dir, ".credentials.json" });
	defer allocator.free(cred_path);

	const connected = blk: {
		// An ABSENT marker is "not connected" on the container backend, which
		// signals disconnect by REMOVING the marker. The VM-family backends keep
		// the file and write "0" instead, so the content is the second state --
		// single-sourced here so the VM's shell wrapper needs no rule of its own.
		cwd.access(io, marker, .{}) catch break :blk false;
		break :blk !markerSaysDisconnected(allocator, io, marker);
	};

	if (connected) {
		// ~/.claude must exist before the cred file lands in it (the oneshot
		// symlinks ~/.claude at this PVC dir; createDirPath is a no-op when present).
		try cwd.createDirPath(io, claude_dir);
		const json = try secret_mod.stubCredentialJson(allocator);
		defer allocator.free(json);
		try writeFile0600(io, cred_path, json);
	} else if (isOurStub(allocator, io, cred_path)) {
		// Disconnected / never-connected: drop OUR OWN stub so claude-code hits
		// /login -- and only ours. An owner who never connected at the cogworx
		// level may have run an in-guest /login, whose REAL credential lands at
		// this exact path and is meant to persist (state PVC / VM overlay). This
		// branch runs on a TIMER (cogworx re-drives the unbind leg for an
		// unconnected owner on every relist), so an unconditional delete logged
		// such a user out over and over.
		cwd.deleteFile(io, cred_path) catch {};
	}
}

/// Did COGBOX write the file at `path`? Only then may reconcile remove it.
///
/// SUBSTRING, never byte-equality: the sentinel ships in three serializations --
/// this verb's compact JSON (secret.stubCredentialJson), the VM launcher's
/// jq-PRETTY write_stub_cred, and that launcher's REDACTOR, which keeps the
/// user's other fields around the sentinel. Comparing against stubCredentialJson
/// would fail to recognise two of the three and so PRESERVE a stale stub on an
/// explicit disconnect -- resurrecting the "appears logged in, every request
/// 401s" state the removal exists to prevent.
///
/// A claude-code that has really logged in-guest cannot keep the sentinel: it can
/// never refresh OUR stub (bogus refreshToken + far-future expiry), but after a
/// /login it self-refreshes with its own token, and every such rewrite drops the
/// sentinel -- so the file is then correctly classified as the user's and kept.
///
/// An EMPTY file counts as ours: it carries no credential and is the one residue
/// a torn stub write can leave (create-truncate, then write), so removing it can
/// lose nothing. A read failure counts as NOT ours -- the non-destructive answer.
fn isOurStub(allocator: std.mem.Allocator, io: std.Io, path: []const u8) bool {
	const data = readSmall(allocator, io, path, .limited(64 * 1024)) orelse return false;
	defer allocator.free(data);
	return data.len == 0 or std.mem.indexOf(u8, data, secret_mod.claude_stub_token) != null;
}

/// Does a PRESENT marker spell the VM-family backends' explicit "not bound"?
///
/// TRIM: the e2e writes `printf '0\n'` (the deleted shell wrapper relied on
/// `$(cat)` stripping it) while the backends write a bare `printf '%s' '0'`. An
/// untrimmed compare would flip an explicit disconnect into a stub STAGE.
/// The container's BOUND marker is an EMPTY file, which trims to "" != "0" and so
/// still reads CONNECTED -- do not invert that. A marker that is present but
/// unreadable keeps today's meaning (stage), the non-destructive direction.
fn markerSaysDisconnected(allocator: std.mem.Allocator, io: std.Io, marker: []const u8) bool {
	const data = readSmall(allocator, io, marker, .limited(64)) orelse return false;
	defer allocator.free(data);
	return std.mem.eql(u8, std.mem.trim(u8, data, " \t\r\n"), "0");
}

/// Bounded read of a REGULAR file, never following a symlink; null on any
/// failure. Both callers are new read surface on paths the guest's own root can
/// write (the state PVC / the overlay), whereas the deleteFile this gates is an
/// unlinkat that can neither follow a link nor block. Guest root could otherwise
/// plant a FIFO and hang a oneshot that other units order themselves before, so
/// stat first and refuse anything that is not a plain file. The bytes are never
/// logged.
fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8, limit: std.Io.Limit) ?[]u8 {
	const cwd = std.Io.Dir.cwd();
	const st = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch return null;
	if (st.kind != .file) return null;
	const f = cwd.openFile(io, path, .{ .follow_symlinks = false }) catch return null;
	defer f.close(io);
	var rbuf: [512]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(allocator, limit) catch null;
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

// Write `bytes` at `<claude_dir>/.credentials.json`, creating the dir. Stands in
// for an in-guest /login (whose credential lands at exactly this path).
fn writeCred(gpa: std.mem.Allocator, io: std.Io, claude_dir: []const u8, bytes: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	try cwd.createDirPath(io, claude_dir);
	const p = try std.fmt.allocPrint(gpa, "{s}/.credentials.json", .{claude_dir});
	defer gpa.free(p);
	try writeFile0600(io, p, bytes);
}

fn writeMarker(io: std.Io, marker: []const u8, bytes: []const u8) !void {
	try writeFile0600(io, marker, bytes);
}

test "claude stub: a credential the user placed in-guest is NEVER removed" {
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

	// An in-guest /login wrote a credential that carries NO cogbox sentinel.
	const user_cred = "{\"claudeAiOauth\":{\"accessToken\":\"oat-placeholder-from-an-in-guest-login\"}}\n";
	try writeCred(gpa, io, claude_dir, user_cred);

	// Never connected at the cogworx level -> no marker, and cogworx re-drives
	// this leg on every relist pass. Two runs stand in for that timer: the
	// user's own bytes must be byte-identical after both.
	try reconcile(gpa, io, claude_dir, marker);
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expectEqualStrings(user_cred, cred);
	}

	// The VM-family backends spell "not bound" as marker content "0" (with a
	// trailing newline in the e2e), for a never-connected owner as well as for an
	// explicit disconnect. That must NOT be read as connected (which would
	// OVERWRITE the user's credential with the stub) nor delete it.
	try writeMarker(io, marker, "0\n");
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expectEqualStrings(user_cred, cred);
	}

	// Our OWN stub is still dropped on an explicit disconnect: bind (marker not
	// "0") stages the sentinel, then unbind ("0") removes it.
	try writeMarker(io, marker, "1\n");
	try reconcile(gpa, io, claude_dir, marker);
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expect(std.mem.indexOf(u8, cred, secret_mod.claude_stub_token) != null);
	}
	try writeMarker(io, marker, "0\n");
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
