// Pure HTTP/1.x request-head parsing for the L7 proxy's plaintext (:80) and
// terminated paths. Extracts the Host (port stripped) and a normalized
// request path (percent-decoded, query stripped, empty segments collapsed) so
// the L7 rule engine can match a boundary-aware path prefix without being
// fooled by `%2F` encoding tricks. A `.` or `..` segment is REFUSED outright
// rather than collapsed -- see normalizePath.
//
// Strict and fail-closed: bare-LF line endings, absent/duplicate Host,
// absolute-form authority != Host (request smuggling / fronting), the h2
// preface, and CONNECT are all rejected. No allocation, no IO.

const std = @import("std");

pub const Parsed = struct {
	host: []const u8, // aliases out_host, port stripped
	path: []const u8, // aliases out_path, normalized
	method: []const u8, // aliases the input `buf`, uppercase (e.g. GET/POST)
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
	// `method` aliases the caller's `buf` (the request bytes), which outlives
	// the returned Parsed on every call site (peek buffer / test fixture).
	return .{ .ok = .{ .host = out_host[0..host.len], .path = norm, .method = method } };
}

pub const Precheck = enum { plausible, deny };

/// Fail-fast "could these bytes still become an HTTP/1.x request line?" check for
/// the peek classifier, run on the bytes buffered so far each recv iteration.
/// Its whole job is to reject a non-HTTP server-speaks-first flow (e.g. an SSH
/// banner "SSH-2.0-...") the instant a byte can't belong to a request line --
/// WITHOUT waiting for a complete head, which for such a flow never arrives and
/// would otherwise cost the entire peek timeout. It never rejects genuine HTTP:
/// an incomplete-but-plausible prefix returns .plausible and parseRequestHead
/// makes the real (byte-identical) decision.
pub fn requestLinePrecheck(buf: []const u8) Precheck {
	// Method: 1..16 uppercase-ASCII bytes terminated by a single SP. Reject the
	// moment a byte can't be part of that -- "SSH-2.0-..." trips on the '-' at
	// offset 3, long before any CRLF.
	var i: usize = 0;
	while (i < buf.len) : (i += 1) {
		const ch = buf[i];
		if (ch == ' ') {
			if (i == 0) return .deny; // empty method
			break; // method [0..i] complete; validate the rest below
		}
		if (ch < 'A' or ch > 'Z') return .deny;
		if (i >= 16) return .deny; // method exceeds 16 bytes without an SP
	}
	if (i >= buf.len) {
		// No SP seen yet: still a plausible in-progress method. Guard only against
		// an unbounded first line that never terminates (mirrors parseRequestHead).
		if (buf.len > max_head) return .deny;
		return .plausible;
	}

	// buf[i] == ' ': the method is valid. Wait for a full request line before
	// validating its shape; until then the prefix stays plausible.
	const eol = std.mem.indexOf(u8, buf, "\r\n") orelse {
		if (buf.len > max_head) return .deny;
		return .plausible;
	};
	const line = buf[0..eol];

	// Full request line present: validate METHOD SP TARGET SP HTTP/1.x, mirroring
	// parseRequestHead's request-line checks. A shape violation here means this
	// was never HTTP -> deny (parseRequestHead would reject it too).
	var rl = std.mem.splitScalar(u8, line, ' ');
	const method = rl.next() orelse return .deny;
	const target = rl.next() orelse return .deny;
	const version = rl.next() orelse return .deny;
	if (rl.next() != null) return .deny; // extra tokens
	if (!isValidMethod(method)) return .deny;
	if (target.len == 0) return .deny;
	if (!std.mem.startsWith(u8, version, "HTTP/1.")) return .deny;
	return .plausible;
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

// pub so path_vectors_test.zig can drive the REAL request-side pipeline
// (strip -> normalize) instead of a copy of it.
pub fn stripQuery(p: []const u8) []const u8 {
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

/// Percent-decode, then collapse empty segments. Returns a slice of `out`
/// (always starts with `/`), or null on overflow / malformed input / a DOT
/// SEGMENT -- and the sole caller turns null into `.deny`.
///
/// WHY A DOT SEGMENT IS REFUSED RATHER THAN COLLAPSED. The enforcer decides on
/// this normalized path but forwards the ORIGINAL raw one upstream, so the two
/// strings must not be able to name different resources. Percent-decoding alone
/// is safe in that respect: a `%2F` becomes a real separator, so decoding can
/// only ever ADD segments, which NARROWS a left-anchored rule (an allow anchored
/// at a literal tail stops matching -- fail closed). Popping `..` is the one
/// step that SUBTRACTS, and `..%2F` puts it under the client's control: a raw
/// path lexically under a deny (`/api/v4/projects/1234/access_tokens/..%2Fissues`)
/// normalizes INTO an allow (`/api/v4/projects/1234/issues`), so the request
/// would be authorized -- and credential-injected -- as one resource while the
/// origin stays free to route the raw form as another. No GitLab REST or git
/// smart-HTTP request needs a `.` or `..` segment, so refusing is cheap and is
/// the only direction that keeps "normalization can only ADD segments" true.
/// Pinned by the shared vector table's `reject` rows.
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
		if (seg.len == 0) continue; // collapse `//`; an empty segment names nothing
		// A `.` or `..` segment is REFUSED, never collapsed -- see the doc comment.
		if (seg.len == 1 and seg[0] == '.') return null;
		if (seg.len == 2 and seg[0] == '.' and seg[1] == '.') return null;
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
	try t.expectEqualStrings("GET", r.ok.method);
}

test "parse strips host port" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET / HTTP/1.1\r\nHost: a.test:8080\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	try t.expectEqualStrings("a.test", r.ok.host);
	try t.expectEqualStrings("/", r.ok.path);
}

test "parse normalizes percent-encoding" {
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	const r = parse("GET /%61dmin/x HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op);
	try t.expect(r == .ok);
	try t.expectEqualStrings("/admin/x", r.ok.path);
}

test "parse DENIES a dot-segment request" {
	// The whole request is refused, not silently rewritten: the decision is made
	// on the normalized path while the RAW one is forwarded, so a step that
	// REMOVES segments would let a request be authorized as one resource and
	// routed by the origin as another. See normalizePath's doc comment.
	var oh: [256]u8 = undefined;
	var op: [256]u8 = undefined;
	try t.expect(parse("GET /api/../%61dmin/./x HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op) == .deny);
	try t.expect(parse("GET /v1/%2e%2e/secret HTTP/1.1\r\nHost: a.test\r\n\r\n", &oh, &op) == .deny);
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

test "precheck: SSH banner denied (full and partial, no CRLF needed)" {
	// The bug this fixes: an SSH banner starts with an uppercase 'S', so
	// isHttpStart routes it here; the precheck must deny it without waiting for a
	// CRLF that never comes.
	try t.expect(requestLinePrecheck("SSH-2.0-OpenSSH_9.9\r\n") == .deny);
	try t.expect(requestLinePrecheck("SSH-") == .deny); // denied on the '-' alone
}

test "precheck: plausible in-progress prefixes are not rejected" {
	try t.expect(requestLinePrecheck("SS") == .plausible); // partial method
	try t.expect(requestLinePrecheck("GET / HT") == .plausible); // partial version
	try t.expect(requestLinePrecheck("GET / HTTP/1.1\r\n") == .plausible); // line ok, head not done
}

test "precheck: malformed request lines denied" {
	try t.expect(requestLinePrecheck("ABCDEFGHIJKLMNOPQ /x HTTP/1.1\r\n") == .deny); // 17-char method
	try t.expect(requestLinePrecheck("GET /x HTTP/1.1 extra\r\n") == .deny); // extra token
	try t.expect(requestLinePrecheck("GET /x FTP/1.1\r\n") == .deny); // not HTTP/1.
	try t.expect(requestLinePrecheck(" /x HTTP/1.1\r\n") == .deny); // empty method
}

test "precheck: genuine methods up to 16 bytes stay plausible" {
	try t.expect(requestLinePrecheck("GET / HTTP/1.1\r\n") == .plausible);
	try t.expect(requestLinePrecheck("ABCDEFGHIJKLMNOP / HTTP/1.1\r\n") == .plausible); // exactly 16
}

test "precheck: a lowercase first byte is out of scope (isHttpStart gates it)" {
	// peekClassify only calls the precheck when isHttpStart(buf[0]) is true, so a
	// lowercase-led flow never reaches here. Documented: it would deny anyway.
	try t.expect(requestLinePrecheck("ssh-2.0\r\n") == .deny);
}

test "normalizePath root, empty segments, and refused dot segments" {
	var op: [256]u8 = undefined;
	try t.expectEqualStrings("/", normalizePath("/", &op).?);
	try t.expectEqualStrings("/a", normalizePath("//a", &op).?);
	// A dot segment is refused outright (the caller denies), in every form:
	// bare, encoded, and the `..%2F` shape that walks INTO an anchored allow.
	try t.expect(normalizePath("/../..", &op) == null);
	try t.expect(normalizePath("/a/./b", &op) == null);
	try t.expect(normalizePath("/v1/%2e%2e/secret", &op) == null);
	try t.expect(normalizePath("/api/v4/projects/1234/access_tokens/..%2Fissues", &op) == null);
	// ...but a segment that merely CONTAINS dots is ordinary data.
	try t.expectEqualStrings("/a/..b/c...", normalizePath("/a/..b/c...", &op).?);
}
