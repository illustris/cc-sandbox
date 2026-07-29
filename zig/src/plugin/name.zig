// Plugin name derivation from flake URLs, plus the plugin-name validator.
//
// The grammar matches instance names (cli/parse.zig isValidName): starts
// with a letter, then [A-Za-z0-9-], max 64 chars. "user" is additionally
// reserved -- it is the composition flake's input name for the per-instance
// user flake. "git-grants" is reserved too: it is the backend-owned L7 rule
// tag (cogworx gitgrants.go gitGrantsTag) that gates credential injection, so
// a plugin must never be able to claim it and thereby stamp `plugin:git-grants`
// on its own rules (see docs/network-filtering.md).

const std = @import("std");

pub const Error = error{
	CannotDerive,
	OutOfMemory,
};

pub const SplitUrl = struct {
	ref: []const u8, // flake URL without the fragment
	attr: ?[]const u8, // module attr from `#attr`, null when absent
};

pub const FragmentError = error{
	EmptyFragment,
	InvalidAttr,
};

/// Split `URL#attr` into the flake ref and the module attr. The attr selects
/// `cogboxPlugins.<attr>` in the plugin flake; absent means `default`.
pub fn splitFragment(url: []const u8) FragmentError!SplitUrl {
	const hash = std.mem.indexOfScalar(u8, url, '#') orelse {
		return .{ .ref = url, .attr = null };
	};
	const attr = url[hash + 1 ..];
	if (attr.len == 0) return error.EmptyFragment;
	if (!isValidAttr(attr)) return error.InvalidAttr;
	return .{ .ref = url[0..hash], .attr = attr };
}

/// Module attrs are restricted to a shell- and nix-safe charset because they
/// are interpolated into `nix eval --apply` expressions and attr paths.
pub fn isValidAttr(s: []const u8) bool {
	if (s.len == 0 or s.len > 128) return false;
	for (s) |c| {
		if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
	}
	return true;
}

/// Plugin name for a fragment add: the attr itself, sanitized to the
/// plugin-name grammar.
pub fn deriveNameFromAttr(allocator: std.mem.Allocator, attr: []const u8) Error![]const u8 {
	return sanitize(allocator, attr);
}

pub fn isValidPluginName(s: []const u8) bool {
	if (s.len == 0 or s.len > 64) return false;
	if (!std.ascii.isAlphabetic(s[0])) return false;
	for (s[1..]) |c| {
		if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
	}
	if (std.mem.eql(u8, s, "user")) return false;
	if (std.mem.eql(u8, s, "git-grants")) return false;
	return true;
}

/// Derive a plugin name from a flake URL. Precedence:
///   1. the last path component of a `?dir=` query param, if present
///   2. registry-style refs (github:, gitlab:, sourcehut:): the repo segment
///   3. otherwise: the last path component, with a `.git` suffix stripped
/// The result is sanitized to the plugin-name grammar; if nothing valid
/// survives, the caller should ask the user for --as.
pub fn deriveName(allocator: std.mem.Allocator, url: []const u8) Error![]const u8 {
	var base = url;
	var query: []const u8 = "";
	if (std.mem.indexOfScalar(u8, url, '?')) |q| {
		base = url[0..q];
		query = url[q + 1 ..];
	}

	if (queryParam(query, "dir")) |dir| {
		return sanitize(allocator, lastComponent(dir));
	}

	var rest: []const u8 = base;
	var registry_style = false;
	if (std.mem.indexOf(u8, base, "://")) |i| {
		// URL style: scheme://host/path -- drop the host segment.
		rest = base[i + 3 ..];
		if (std.mem.indexOfScalar(u8, rest, '/')) |s| {
			rest = rest[s + 1 ..];
		} else {
			return error.CannotDerive;
		}
	} else if (std.mem.indexOfScalar(u8, base, ':')) |i| {
		const scheme = base[0..i];
		rest = base[i + 1 ..];
		registry_style = std.mem.eql(u8, scheme, "github") or
			std.mem.eql(u8, scheme, "gitlab") or
			std.mem.eql(u8, scheme, "sourcehut");
	}

	var src: []const u8 = undefined;
	if (registry_style) {
		// owner/repo[/ref] -- the repo segment names the plugin; a trailing
		// ref (branch or rev) is not part of the name.
		var it = std.mem.splitScalar(u8, rest, '/');
		_ = it.next() orelse return error.CannotDerive; // owner
		src = it.next() orelse return error.CannotDerive;
	} else {
		src = lastComponent(rest);
	}

	if (std.mem.endsWith(u8, src, ".git")) src = src[0 .. src.len - 4];
	return sanitize(allocator, src);
}

fn lastComponent(path: []const u8) []const u8 {
	const trimmed = std.mem.trimEnd(u8, path, "/");
	if (std.mem.lastIndexOfScalar(u8, trimmed, '/')) |i| {
		return trimmed[i + 1 ..];
	}
	return trimmed;
}

fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
	var it = std.mem.splitScalar(u8, query, '&');
	while (it.next()) |pair| {
		const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
		if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
	}
	return null;
}

/// Map to the plugin-name grammar: `_` and `.` become `-`, other invalid
/// characters are dropped, leading non-letters and trailing dashes are
/// trimmed, and the result is truncated to 64 chars.
fn sanitize(allocator: std.mem.Allocator, src: []const u8) Error![]const u8 {
	var buf: std.ArrayList(u8) = .empty;
	defer buf.deinit(allocator);

	for (src) |c| {
		if (std.ascii.isAlphanumeric(c) or c == '-') {
			try buf.append(allocator, c);
		} else if (c == '_' or c == '.') {
			try buf.append(allocator, '-');
		}
	}

	var s: []const u8 = buf.items;
	while (s.len > 0 and !std.ascii.isAlphabetic(s[0])) s = s[1..];
	while (s.len > 0 and s[s.len - 1] == '-') s = s[0 .. s.len - 1];
	if (s.len > 64) s = s[0..64];
	if (!isValidPluginName(s)) return error.CannotDerive;
	return try allocator.dupe(u8, s);
}
