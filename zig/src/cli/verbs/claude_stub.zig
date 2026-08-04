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
//     over it), but ONLY over an absent file or our own sentinel. The real
//     token never enters the agent -- only the inert stub is ever written here.
//   marker "0" (the VM-family backends' explicit "not bound") or ABSENT (the
//     container clears the marker instead) -> remove the stub, but ONLY when the
//     file carries our own sentinel.
//
// BOTH legs are gated the same way, because a credential the sandbox user
// obtained with an in-guest /login lands at this exact path and is THEIRS: the
// in-guest session must supersede the host-managed identity, so this verb never
// removes and never overwrites a file it did not write itself.
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
/// stub when `marker` says bound -- writing only over an absent file or OUR OWN
/// sentinel -- else remove OUR OWN stub. Idempotent (a boot oneshot + a
/// connect/disconnect trigger both call it), so a re-run with the marker present
/// leaves the stub in place -- the basis for restart persistence. Pure of the
/// real token: the only value it ever writes is the shared sentinel stub.
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
		// symlinks ~/.claude at this PVC dir; createDirPath is a no-op when
		// present). It stays ABOVE the gate: on a fresh instance the dir does
		// not exist yet and the absent-branch write needs somewhere to land.
		try cwd.createDirPath(io, claude_dir);
		// Write ONLY over what cogbox wrote -- the mirror image of the removal
		// rule below. A credential the sandbox user obtained with an in-guest
		// /login lands at this exact path and MUST supersede the host-managed
		// identity; this oneshot re-runs at every boot and cogworx restarts it
		// on every lifecycle re-drive, so an unconditional stamp logged such a
		// user out again on each restart. Nothing is weakened by keeping it:
		// the mitm addon stamps the owner's Bearer only over an empty or
		// exactly-stub credential and forwards any other one upstream
		// untouched, so a preserved token can never carry another identity.
		const decision: StageDecision = blk: {
			// ABSENT is the one state isOurStub cannot express: readSmall stats
			// first and maps every failure to null, so a MISSING file reads as
			// "not ours" -- right for a delete, wrong here. Gating on isOurStub
			// alone would skip the very FIRST stage and never arm the feature.
			// Stat NO-FOLLOW, as readSmall does, so a symlink is "present, not
			// ours" and is never written THROUGH; every stat failure other than
			// a genuinely missing path is not-writable, the non-destructive
			// answer this file already takes for an unreadable credential.
			if (cwd.statFile(io, cred_path, .{ .follow_symlinks = false })) |_| {
				break :blk if (isOurStub(allocator, io, cred_path)) .stage else .keep_foreign;
			} else |err| {
				break :blk if (err == error.FileNotFound) .stage else .{ .unreadable = err };
			}
		};
		switch (decision) {
			.stage => {
				const json = try secret_mod.stubCredentialJson(allocator);
				defer allocator.free(json);
				try writeFile0600(io, cred_path, json);
			},
			// A skip must be LOUD, because nothing else can show it: the unit is
			// Type=oneshot RemainAfterExit=true (so it reads `active (exited)`)
			// and cogworx's stub probes read the MARKER, never the credential, so
			// a skipped stage still reports "bound/staged" in the UI. Without a
			// line here, "the user's own credential is in charge" and "the path
			// was unreadable" both look exactly like a healthy stage, and a "Not
			// logged in" report has no signal to go on. Silence on the staging
			// path is then unambiguous: a warning appears iff nothing was written.
			.keep_foreign => warnSkip(allocator, io, "__claude-stub: {s} carries no cogbox stub sentinel (or is not a readable regular file), so it is the sandbox user's own credential and supersedes the host-managed one: leaving it alone, NOT staging the stub", .{cred_path}),
			.unreadable => |err| warnSkip(allocator, io, "__claude-stub: cannot inspect {s} ({s}); NOT staging the stub (refusing to truncate a file that may be the sandbox user's own credential)", .{ cred_path, @errorName(err) }),
		}
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

/// Warn to STDERR about a skipped stage -- the reason only, never the file's
/// bytes. Quiet under the test runner: stdout is the zig test protocol (see
/// secret.zig's `announce`), and a test step that writes to STDERR makes
/// `zig build test` print it as "failed command" even when every test passed,
/// i.e. a green gate that reads red. A failed log write never fails a reconcile.
fn warnSkip(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) void {
	if (@import("builtin").is_test) return;
	util.warn(allocator, io, fmt, args) catch {};
}

/// What the bind leg decided about the credential path -- carried out of the
/// probe so a SKIP can name its reason in the journal instead of looking exactly
/// like a healthy stage. `isOurStub` stays the only content predicate.
const StageDecision = union(enum) {
	/// Absent, or ours (empty / carries the sentinel): safe to (re-)write.
	stage,
	/// Present but not ours. Usually the credential an in-guest /login wrote;
	/// also anything readSmall refuses (symlink, FIFO, >64KB, unreadable), which
	/// takes the same non-destructive answer, so the message says both.
	keep_foreign,
	/// The path could not even be stat'ed (EIO, ELOOP, EACCES, ...).
	unreadable: anyerror,
};

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

// Remove `<claude_dir>/.credentials.json`. Stands in for the documented escape
// hatch back to host-managed auth: an in-guest /logout (or an `rm`), after which
// the bind leg's ABSENT branch may stage the sentinel again.
fn deleteCred(gpa: std.mem.Allocator, io: std.Io, claude_dir: []const u8) !void {
	const p = try std.fmt.allocPrint(gpa, "{s}/.credentials.json", .{claude_dir});
	defer gpa.free(p);
	try std.Io.Dir.cwd().deleteFile(io, p);
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
	// "0") stages the sentinel, then unbind ("0") removes it. The user's own
	// credential must go first -- the bind leg refuses to write over it, which is
	// the documented escape hatch back to host-managed auth: only once the user
	// clears their own credential (an in-guest /logout) may the stub stage again.
	try deleteCred(gpa, io, claude_dir);
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

test "claude stub: a credential the user placed in-guest is NEVER overwritten" {
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

	// The owner IS connected, so cogworx keeps re-driving the BIND leg: at every
	// boot of the oneshot and on every lifecycle re-drive. The user's in-guest
	// session must supersede that, so their bytes stay byte-identical across all
	// of it -- both marker spellings of BOUND included ("1" on the VM-family
	// backends, an EMPTY file on the container, which trims to "" != "0").
	try writeMarker(io, marker, "1\n");
	try reconcile(gpa, io, claude_dir, marker);
	try reconcile(gpa, io, claude_dir, marker);
	try writeMarker(io, marker, "");
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expectEqualStrings(user_cred, cred);
	}

	// The gate must still let the FIRST stage through, or every sandbox ends up
	// stubless: ABSENT is the one state isOurStub cannot express, so gating the
	// write on isOurStub alone would disarm the feature entirely. Clearing the
	// credential (the escape hatch: an in-guest /logout) resumes host-managed
	// auth on the next run of the oneshot.
	try deleteCred(gpa, io, claude_dir);
	try writeMarker(io, marker, "1\n");
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expect(credExists(io, claude_dir));
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expect(std.mem.indexOf(u8, cred, secret_mod.claude_stub_token) != null);
	}

	// ...and re-staging over OUR OWN stub stays idempotent (restart persistence).
	try reconcile(gpa, io, claude_dir, marker);
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expect(std.mem.indexOf(u8, cred, secret_mod.claude_stub_token) != null);
	}

	// A ZERO-BYTE credential is OURS and must stay writable -- the second state
	// (besides ABSENT) the gate has to let through, and the only self-heal for a
	// TORN stub write: writeFile0600 create-truncates and only then writes, so a
	// pod OOM-kill or eviction between those two syscalls leaves exactly a 0-byte
	// file. If that clause were ever "hardened" away, the bind leg would refuse
	// forever -- every boot and every re-drive -- and a connected owner's sandbox
	// would stay permanently stubless while the marker still reads bound, so the
	// 5m sweep would skip it too. Pinned here because no other test covers it.
	try writeCred(gpa, io, claude_dir, "");
	try reconcile(gpa, io, claude_dir, marker);
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expect(std.mem.indexOf(u8, cred, secret_mod.claude_stub_token) != null);
	}
}

test "claude stub: a symlink at the cred path is never written THROUGH" {
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

	// Guest root can write this path, so it can plant a DANGLING symlink there.
	// The bind leg's presence probe must therefore stat NO-FOLLOW: `access` (or any
	// following stat) reports a dangling link as ABSENT, and createFile would then
	// write the stub THROUGH it, at a path the guest chose. A symlink is instead
	// "present, not ours" -> skipped. Losing the stub in that case is the harmless
	// direction (the stub is inert and the guest broke its own inheritance).
	try cwd.createDirPath(io, claude_dir);
	const link = try std.fmt.allocPrint(gpa, "{s}/.credentials.json", .{claude_dir});
	defer gpa.free(link);
	const target = try std.fmt.allocPrint(gpa, "{s}/would-be-clobbered", .{root});
	defer gpa.free(target);
	try cwd.symLink(io, target, link, .{});

	try writeMarker(io, marker, "1\n");
	try reconcile(gpa, io, claude_dir, marker);
	try std.testing.expectError(error.FileNotFound, cwd.statFile(io, target, .{}));

	// The unbind leg agrees (readSmall refuses a non-regular file), so the link is
	// not removed either -- both legs simply leave what is not ours alone.
	try writeMarker(io, marker, "0\n");
	try reconcile(gpa, io, claude_dir, marker);
	{
		const st = try cwd.statFile(io, link, .{ .follow_symlinks = false });
		try std.testing.expectEqual(std.Io.File.Kind.sym_link, st.kind);
	}
}

test "claude stub: a cred path that cannot be STAT'd is never truncated" {
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
	const cred_path = try std.fmt.allocPrint(gpa, "{s}/.credentials.json", .{claude_dir});
	defer gpa.free(cred_path);

	// An in-guest /login wrote a credential that carries NO cogbox sentinel...
	const user_cred = "{\"claudeAiOauth\":{\"accessToken\":\"oat-placeholder-from-an-in-guest-login\"}}\n";
	try writeCred(gpa, io, claude_dir, user_cred);

	// ...and then the path stopped being STAT-able while the file itself stayed
	// put -- the state the bind leg's `err == error.FileNotFound` narrowing exists
	// for, and the only one no other test here reaches (a symlink, a FIFO and a
	// directory all STAT fine no-follow and land in `keep_foreign` instead).
	// Dropping the claude dir's SEARCH bit is the portable stand-in for the field
	// shapes: a ceph-csi remount handing back EIO, or the dir losing a mode/ACL
	// under the state PVC. READ is kept, so reconcile's createDirPath still sees
	// an existing directory; all the gate needs is a stat that fails with
	// something OTHER than FileNotFound.
	const no_search = std.Io.File.Permissions.fromMode(0o400);
	const restored = std.Io.File.Permissions.fromMode(0o700);
	try cwd.setFilePermissions(io, claude_dir, no_search, .{});
	// Registered AFTER the deleteTree defer above, so it runs BEFORE it (LIFO):
	// teardown needs the search+write bits back to unlink the credential.
	defer cwd.setFilePermissions(io, claude_dir, restored, .{}) catch {};

	// Root ignores a missing search bit (CAP_DAC_OVERRIDE), so under root this
	// test cannot reach the state it exists to pin -- skip loudly rather than
	// pass vacuously. The nix check builds unprivileged, so the gate does cover
	// it; only a root-run `zig build test` skips.
	if (cwd.statFile(io, cred_path, .{ .follow_symlinks = false })) |_| {
		return error.SkipZigTest;
	} else |err| if (err == error.FileNotFound) return error.SkipZigTest;

	// The owner IS connected, so the BIND leg runs -- and that narrowing is the
	// one clause between this state and a truncating write: classify any stat
	// failure as "absent, safe to stage" and writeFile0600 create-TRUNCATES what
	// may be the sandbox user's own credential, the exact loss this verb exists
	// to prevent. The skip must also not fail the run: the oneshot is ordered
	// before other units, so an error here would cascade into the boot.
	try writeMarker(io, marker, "1\n");
	try reconcile(gpa, io, claude_dir, marker);

	// Give the search bit back (the transient EIO/mode change healed) and read:
	// the user's bytes, untouched, and no sentinel stamped over them.
	try cwd.setFilePermissions(io, claude_dir, restored, .{});
	{
		const cred = try readCred(gpa, io, claude_dir);
		defer gpa.free(cred);
		try std.testing.expectEqualStrings(user_cred, cred);
	}
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
