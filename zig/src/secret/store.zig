// Host-only named secret store for cogbox.
//
// An operator binds a credential by NAME, host-side, with `cogbox secret add`.
// The value lives at <dir>/<name> (the raw secret, 0600) and metadata at
// <dir>/<name>.meta (JSON: audience, kind, tier, bound-at). The global store is
// <config>/secrets/; sidecar-produced per-instance secrets use the same layout
// under <config>/instances/<inst>/secrets/.
//
// SECURITY: the store NEVER holds a path or value chosen by a plugin -- a plugin
// only NAMES a secret it wants injected and the AUDIENCE host it targets; the
// operator binds the real value here. The `audience` in the meta is the host(s)
// the secret may be injected to; the inject-conf renderer refuses to emit a spec
// whose host is not the bound secret's audience, so a hostile plugin cannot
// redirect a bound secret to an attacker host. Nothing here is shared into the
// guest.
//
// This file is split into a PURE layer (validName / buildMeta / parseMeta --
// unit-tested) and an IO layer (add / lookup / remove -- covered by the
// launcher + NixOS VM integration tests, mirroring how rules/config.zig leaves
// its load/save IO to integration coverage).

const std = @import("std");

// --- pure layer ------------------------------------------------------------

/// A secret name: 1..64 chars, charset [A-Za-z0-9_-]. Excludes '.' and '/', so
/// neither `<name>` nor the derived `<name>.meta` can traverse out of the store
/// directory. This is the same shape a plugin manifest's `secret` field must
/// satisfy (validated again plugin-side before it reaches config.json).
pub fn validName(name: []const u8) bool {
	if (name.len == 0 or name.len > 64) return false;
	for (name) |c| switch (c) {
		'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => {},
		else => return false,
	};
	return true;
}

pub const Meta = struct {
	/// Exact host(s) the secret may be injected to. null = unset = not
	/// injectable (the renderer skips it and `secret ls` flags it).
	audience: ?[]const u8 = null,
	/// Injection style hint: "bearer" | "cookie" (others are harness-internal).
	kind: []const u8 = "bearer",
	/// "durable" (a long-lived operator secret) | "derived" (a short-lived
	/// session minted by a sidecar). A derived secret may not be bound as a
	/// sidecar loginSecret.
	tier: []const u8 = "durable",
	bound_at: ?i64 = null,
};

pub fn appendJsonString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	try out.append(allocator, '"');
	for (s) |c| switch (c) {
		'"' => try out.appendSlice(allocator, "\\\""),
		'\\' => try out.appendSlice(allocator, "\\\\"),
		'\n' => try out.appendSlice(allocator, "\\n"),
		'\r' => try out.appendSlice(allocator, "\\r"),
		'\t' => try out.appendSlice(allocator, "\\t"),
		0...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
			var b: [8]u8 = undefined;
			try out.appendSlice(allocator, std.fmt.bufPrint(&b, "\\u{x:0>4}", .{c}) catch unreachable);
		},
		else => try out.append(allocator, c),
	};
	try out.append(allocator, '"');
}

/// Serialize `meta` to its on-disk JSON form (jq --tab shape). Pure.
pub fn buildMeta(allocator: std.mem.Allocator, meta: Meta) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	errdefer out.deinit(allocator);
	try out.appendSlice(allocator, "{\n\t\"audience\": ");
	if (meta.audience) |a| try appendJsonString(allocator, &out, a) else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, ",\n\t\"kind\": ");
	try appendJsonString(allocator, &out, meta.kind);
	try out.appendSlice(allocator, ",\n\t\"tier\": ");
	try appendJsonString(allocator, &out, meta.tier);
	try out.appendSlice(allocator, ",\n\t\"bound_at\": ");
	if (meta.bound_at) |b| {
		var nb: [32]u8 = undefined;
		try out.appendSlice(allocator, std.fmt.bufPrint(&nb, "{d}", .{b}) catch unreachable);
	} else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, "\n}\n");
	return out.toOwnedSlice(allocator);
}

/// Parse the meta JSON `text`. Missing/invalid fields fall back to defaults
/// (audience null, kind "bearer"). String fields are dup'd into `allocator`.
/// Pure (no IO).
pub fn parseMeta(allocator: std.mem.Allocator, text: []const u8) !Meta {
	var meta: Meta = .{};
	var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch return meta;
	defer parsed.deinit();
	const root = parsed.value;
	if (root != .object) return meta;
	if (root.object.get("audience")) |v| {
		if (v == .string) meta.audience = try allocator.dupe(u8, v.string);
	}
	if (root.object.get("kind")) |v| {
		if (v == .string) meta.kind = try allocator.dupe(u8, v.string);
	}
	if (root.object.get("tier")) |v| {
		if (v == .string) meta.tier = try allocator.dupe(u8, v.string);
	}
	if (root.object.get("bound_at")) |v| {
		if (v == .integer) meta.bound_at = v.integer;
	}
	return meta;
}

// --- IO layer --------------------------------------------------------------

fn metaPath(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
	const base = try std.fmt.allocPrint(allocator, "{s}.meta", .{name});
	defer allocator.free(base);
	return std.fs.path.join(allocator, &.{ dir, base });
}

/// Atomically write `bytes` to `path` with mode 0600 (.tmp + rename).
fn writeFile0600(allocator: std.mem.Allocator, io: std.Io, path: []const u8, bytes: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const tmp = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
	defer allocator.free(tmp);
	{
		const f = try cwd.createFile(io, tmp, .{ .truncate = true, .permissions = std.Io.File.Permissions.fromMode(0o600) });
		defer f.close(io);
		var wbuf: [4096]u8 = undefined;
		var w = f.writer(io, &wbuf);
		try w.interface.writeAll(bytes);
		try w.flush();
		try f.sync(io);
	}
	try cwd.rename(tmp, cwd, path, io);
}

fn readAll(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ?[]u8 {
	const cwd = std.Io.Dir.cwd();
	const f = cwd.openFile(io, path, .{}) catch return null;
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20)) catch null;
}

/// Bind `name` to `value` (0600) plus its `meta` sidecar, under `dir`
/// (created 0700-ish if absent). Overwrites atomically (rotation-safe).
pub fn add(allocator: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8, value: []const u8, meta: Meta) !void {
	if (!validName(name)) return error.InvalidName;
	const cwd = std.Io.Dir.cwd();
	try cwd.createDirPath(io, dir);

	const vpath = try std.fs.path.join(allocator, &.{ dir, name });
	defer allocator.free(vpath);
	try writeFile0600(allocator, io, vpath, value);

	const mpath = try metaPath(allocator, dir, name);
	defer allocator.free(mpath);
	const mjson = try buildMeta(allocator, meta);
	defer allocator.free(mjson);
	try writeFile0600(allocator, io, mpath, mjson);
}

/// Remove a bound secret + its meta. Returns true if the value file existed.
pub fn remove(allocator: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8) !bool {
	if (!validName(name)) return error.InvalidName;
	const cwd = std.Io.Dir.cwd();
	const vpath = try std.fs.path.join(allocator, &.{ dir, name });
	defer allocator.free(vpath);
	const mpath = try metaPath(allocator, dir, name);
	defer allocator.free(mpath);
	var existed = true;
	cwd.access(io, vpath, .{}) catch {
		existed = false;
	};
	cwd.deleteFile(io, vpath) catch {};
	cwd.deleteFile(io, mpath) catch {};
	return existed;
}

/// Enumerate the BOUND secret names under `dir` (value files present; the
/// `.meta` sidecars and `.tmp` write-temps are skipped, invalid names ignored).
/// Names are dup'd into `allocator` -- pass an arena. A never-bound store (no
/// dir yet) yields an empty list, not an error. Used by the container enforcer
/// render to seed an inject spec per bound git secret (it can't know provider
/// names a priori, unlike the single reserved claude-oauth secret).
pub fn listBound(allocator: std.mem.Allocator, io: std.Io, dir: []const u8) ![][]const u8 {
	var out: std.ArrayList([]const u8) = .empty;
	errdefer out.deinit(allocator);
	const cwd = std.Io.Dir.cwd();
	var d = cwd.openDir(io, dir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => return out.toOwnedSlice(allocator),
		else => return err,
	};
	defer d.close(io);
	var iter = d.iterate();
	while (try iter.next(io)) |entry| {
		if (entry.kind != .file) continue;
		if (std.mem.endsWith(u8, entry.name, ".meta")) continue;
		if (std.mem.endsWith(u8, entry.name, ".tmp")) continue;
		if (!validName(entry.name)) continue;
		try out.append(allocator, try allocator.dupe(u8, entry.name));
	}
	return out.toOwnedSlice(allocator);
}

pub const Resolved = struct {
	/// Absolute path of the value file (the addon reads this as cred_file).
	/// Allocated in the `allocator` passed to lookup.
	value_path: []const u8,
	/// True iff the value file exists (an unbound spec is skipped by the
	/// renderer -- fail closed).
	bound: bool,
	meta: Meta,
};

/// Resolve a secret by (dir, name). Returns null only for an invalid name.
/// Strings are allocated in `allocator` -- pass an arena you own (the renderer
/// passes the loaded config's tree allocator).
pub fn lookup(allocator: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8) !?Resolved {
	if (!validName(name)) return null;
	const value_path = try std.fs.path.join(allocator, &.{ dir, name });
	const cwd = std.Io.Dir.cwd();
	var bound = true;
	cwd.access(io, value_path, .{}) catch {
		bound = false;
	};
	var meta: Meta = .{};
	const mpath = try metaPath(allocator, dir, name);
	defer allocator.free(mpath);
	if (readAll(allocator, io, mpath)) |txt| {
		defer allocator.free(txt);
		meta = try parseMeta(allocator, txt);
	}
	return Resolved{ .value_path = value_path, .bound = bound, .meta = meta };
}
