// Pure HTTP/1.x request-head parsing for the L7 proxy's plaintext (:80) and
// terminated paths. Extracts the Host (port stripped) and a normalized
// request path (percent-decoded, dot-segments collapsed, query stripped) so
// the L7 rule engine can match a boundary-aware path prefix without being
// fooled by `%2e%2e` / `/a/../b` tricks.
//
// Strict and fail-closed: bare-LF line endings, absent/duplicate Host,
// absolute-form authority != Host (request smuggling / fronting), the h2
// preface, and CONNECT are all rejected. No allocation, no IO.

const std = @import("std");

pub const Parsed = struct {
	host: []const u8, // aliases out_host, port stripped
	path: []const u8, // aliases out_path, normalized
};

pub const ParseResult = union(enum) {
	ok: Parsed,
	need_more, // request head not fully buffered yet
	deny,
};

const max_head: usize = 8 * 1024;

pub fn parseRequestHead(buf: []const u8, out_host: []u8, out_path: []u8) ParseResult {
	const head_end = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse {
		if (buf.len >= max_head) return .deny;
		return .need_more;
	};
	const head = buf[0..head_end];
	if (head.len > max_head) return .deny;

	// Reject any bare LF in the head (every '\n' must follow a '\r').
	for (head, 0..) |ch, i| {
		if (ch == '\n' and (i == 0 or head[i - 1] != '\r')) return .deny;
	}

	var lines = std.mem.splitSequence(u8, head, "\r\n");
	const request_line = lines.next() orelse return .deny;

	// --- request line: METHOD SP TARGET SP HTTP/1.x ---
	var rl = std.mem.splitScalar(u8, request_line, ' ');
	const method = rl.next() orelse return .deny;
	const target = rl.next() orelse return .deny;
	const version = rl.next() orelse return .deny;
	if (rl.next() != null) return .deny; // extra tokens
	if (!isValidMethod(method)) return .deny;
	if (std.mem.eql(u8, method, "CONNECT")) return .deny;
	if (std.mem.eql(u8, method, "PRI")) return .deny; // HTTP/2 preface
	if (!std.mem.startsWith(u8, version, "HTTP/1.")) return .deny;

	// --- headers: find Host (exactly once), reject h2c upgrade ---
	var host_val: ?[]const u8 = null;
	while (lines.next()) |line| {
		if (line.len == 0) continue;
		const colon = std.mem.indexOfScalar(u8, line, ':') orelse return .deny;
		const name = line[0..colon];
		const value = trimOws(line[colon + 1 ..]);
		if (eqlIgnoreCase(name, "host")) {
			if (host_val != null) return .deny; // duplicate Host
			host_val = value;
		} else if (eqlIgnoreCase(name, "upgrade")) {
			if (containsIgnoreCase(value, "h2c")) return .deny;
		}
	}
	const host_hdr = host_val orelse return .deny; // HTTP/1.0 without Host -> deny
	const host = stripPort(host_hdr) orelse return .deny;
	if (host.len == 0 or host.len > out_host.len) return .deny;

	// --- target -> (authority?, raw path) ---
	var raw_path: []const u8 = undefined;
	if (std.mem.eql(u8, target, "*")) {
		return .deny; // asterisk-form: no routable host
	} else if (target.len > 0 and target[0] == '/') {
		raw_path = stripQuery(target);
	} else if (std.mem.startsWith(u8, target, "http://") or std.mem.startsWith(u8, target, "https://")) {
		// absolute-form: authority must agree with Host (anti-smuggling)
		const after = target[(std.mem.indexOf(u8, target, "://").?) + 3 ..];
		const slash = std.mem.indexOfScalar(u8, after, '/');
		const authority = if (slash) |s| after[0..s] else after;
		const abs_host = stripPort(authority) orelse return .deny;
		if (!eqlIgnoreCase(abs_host, host)) return .deny;
		raw_path = if (slash) |s| stripQuery(after[s..]) else "/";
	} else {
		return .deny; // authority-form / unknown
	}

	const norm = normalizePath(raw_path, out_path) orelse return .deny;
	@memcpy(out_host[0..host.len], host);
	return .{ .ok = .{ .host = out_host[0..host.len], .path = norm } };
}

fn isValidMethod(m: []const u8) bool {
	if (m.len == 0 or m.len > 16) return false;
	for (m) |ch| {
		if (ch < 'A' or ch > 'Z') return false;
	}
	return true;
}

fn trimOws(s: []const u8) []const u8 {
	return std.mem.trim(u8, s, " \t");
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
	return std.ascii.eqlIgnoreCase(a, b);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
	if (needle.len == 0 or needle.len > haystack.len) return false;
	var i: usize = 0;
	while (i + needle.len <= haystack.len) : (i += 1) {
		if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
	}
	return false;
}

fn stripQuery(p: []const u8) []const u8 {
	const q = std.mem.indexOfAny(u8, p, "?#") orelse return p;
	return p[0..q];
}

/// Strip a trailing `:port` from a Host value. IPv6 literals (`[::1]:80`)
/// are not valid vhost names, so reject them outright.
fn stripPort(h: []const u8) ?[]const u8 {
	if (h.len == 0) return null;
	if (h[0] == '[') return null; // IPv6 literal host: not a name we route
	if (std.mem.lastIndexOfScalar(u8, h, ':')) |idx| return h[0..idx];
	return h;
}

fn isHex(ch: u8) bool {
	return (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F');
}
fn hexVal(ch: u8) u8 {
	if (ch >= '0' and ch <= '9') return ch - '0';
	if (ch >= 'a' and ch <= 'f') return ch - 'a' + 10;
	return ch - 'A' + 10;
}

/// Percent-decode then collapse `.`/`..`/empty segments. Returns a slice of
/// `out` (always starts with `/`), or null on overflow / malformed input.
pub fn normalizePath(raw: []const u8, out: []u8) ?[]const u8 {
	var dec: [4096]u8 = undefined;
	var dn: usize = 0;
	var i: usize = 0;
	while (i < raw.len) {
		if (dn >= dec.len) return null;
		if (raw[i] == '%' and i + 2 < raw.len and isHex(raw[i + 1]) and isHex(raw[i + 2])) {
			dec[dn] = (hexVal(raw[i + 1]) << 4) | hexVal(raw[i + 2]);
			dn += 1;
			i += 3;
		} else {
			dec[dn] = raw[i];
			dn += 1;
			i += 1;
		}
	}
	const decoded = dec[0..dn];
	if (decoded.len == 0 or decoded[0] != '/') return null; // must be absolute

	const trailing_slash = decoded[decoded.len - 1] == '/';

	const Seg = struct { off: usize, len: usize };
	var segs: [128]Seg = undefined;
	var ns: usize = 0;

	var it = std.mem.splitScalar(u8, decoded, '/');
	while (it.next()) |seg| {
		if (seg.len == 0 or (seg.len == 1 and seg[0] == '.')) continue; // collapse // and /./
		if (seg.len == 2 and seg[0] == '.' and seg[1] == '.') {
			if (ns > 0) ns -= 1; // pop
			continue;
		}
		if (ns >= segs.len) return null;
		const off = @intFromPtr(seg.ptr) - @intFromPtr(decoded.ptr);
		segs[ns] = .{ .off = off, .len = seg.len };
		ns += 1;
	}

	var on: usize = 0;
	if (ns == 0) {
		if (out.len < 1) return null;
		out[0] = '/';
		return out[0..1];
	}
	for (segs[0..ns]) |s| {
		if (on + 1 + s.len > out.len) return null;
		out[on] = '/';
		on += 1;
		@memcpy(out[on .. on + s.len], decoded[s.off .. s.off + s.len]);
		on += s.len;
	}
	if (trailing_slash) {
		if (on + 1 > out.len) return null;
		out[on] = '/';
		on += 1;
	}
	return out[0..on];
}

// --- Tests ---

const t = std.testing;

fn parse(req: []const u8, oh: []u8, op: []u8) ParseResult {
	return parseRequestHead(req, oh, op);
}

test "parse basic GET" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET /v1/x?q=1 HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	try t.expectEqualStrings("vhost-a.test", r.ok.host);
	try t.expectEqualStrings("/v1/x", r.ok.path);
}

test "parse strips host port" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET / HTTP/1.1\r\nHost: a.test:8080\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	try t.expectEqualStrings("a.test", r.ok.host);
	try t.expectEqualStrings("/", r.ok.path);
}

test "parse normalizes dot-segments and percent-encoding" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET /api/../%61dmin/./x HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	try t.expectEqualStrings("/admin/x", r.ok.path);
}

test "parse rejects %2e%2e traversal" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET /v1/%2e%2e/secret HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	// /v1/../secret -> /secret  (so a rule on /v1/ would NOT match)
	try t.expectEqualStrings("/secret", r.ok.path);
}

test "parse preserves trailing slash" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET /v1/ HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	try t.expectEqualStrings("/v1/", r.ok.path);
}

test "parse absolute-form must match Host" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const ok = parse("GET http://a.test/p HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op);
	try t.expect(ok == .ok);
	try t.expectEqualStrings("/p", ok.ok.path);
	const bad = parse("GET http://b.test/p HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op);
	try t.expect(bad == .deny);
}

test "parse rejects duplicate Host, no Host, bare LF, h2 preface, CONNECT, h2c" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	try t.expect(parse("GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n", &oh, &op) == .deny);
	try t.expect(parse("GET / HTTP/1.1\r\n\r\n", &oh, &op) == .deny);
	try t.expect(parse("GET / HTTP/1.1\nHost: a.test\n\n", &oh, &op) != .ok); // bare LF
	try t.expect(parse("PRI * HTTP/2.0\r\n\r\n", &oh, &op) == .deny);
	try t.expect(parse("CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op) == .deny);
	try t.expect(parse("GET / HTTP/1.1\r\nHost: a.test\r\nUpgrade: h2c\r\n\r\n", &oh, &op) == .deny);
}

test "parse need_more on partial head" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	try t.expect(parse("GET / HTTP/1.1\r\nHost: a.te", &oh, &op) == .need_more);
}

test "normalizePath root and pops past root" {
	var op: [256]u8 = undefined;
	try t.expectEqualStrings("/", normalizePath("/", &op).?);
	try t.expectEqualStrings("/", normalizePath("/../..", &op).?);
	try t.expectEqualStrings("/a", normalizePath("//a", &op).?);
}
