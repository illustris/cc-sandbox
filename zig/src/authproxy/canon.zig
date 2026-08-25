// Segment-first single-decode canonicalization for the auth proxy.
//
// This is the deferred raw-segment fix (docs/gitlab-sandbox-access.md's §residual)
// obtained by ordering two operations correctly: the raw target is split on `/`
// FIRST and each segment is percent-decoded exactly ONCE. `grp%2Fproj` therefore
// stays ONE segment whose value CONTAINS a slash, so segment positions stay
// stable and an encoded slash becomes a typed fact instead of structural
// inflation -- the property that closes every tail-absorption escape in the
// shared vector table (path_vectors.tsv:201/204/228/237/241/242).
//
// PURE: no IO, no allocation. Callers provide the decode buffer and the segment
// slice array. Every refusal is an enum the core turns into a 403 with no
// credential read and no upstream request.

const std = @import("std");

pub const max_segments = 32;
pub const max_segment_len = 255;
pub const max_query_params = 64;

/// Why the canonicalizer refused a request. Coarse, fixed vocabulary -- these
/// feed the audit line's `reason=` field, never free text.
pub const Refusal = enum {
	invalid_escape,
	bad_byte,
	invalid_utf8,
	dot_segment,
	segment_too_long,
	too_many_segments,
	not_origin_form,
	query_invalid,
	query_too_many,
};

/// The target split at the first `#` (fragment: stripped with everything after
/// it) and then the first `?`. The query is never re-concatenated unparsed.
pub const Target = struct {
	path: []const u8,
	query: []const u8,
};

pub fn splitTarget(raw: []const u8) Target {
	const nofrag = if (std.mem.indexOfScalar(u8, raw, '#')) |i| raw[0..i] else raw;
	if (std.mem.indexOfScalar(u8, nofrag, '?')) |q| {
		return .{ .path = nofrag[0..q], .query = nofrag[q + 1 ..] };
	}
	return .{ .path = nofrag, .query = "" };
}

pub const PathResult = union(enum) {
	ok: usize, // number of segments written into `segs`
	refuse: Refusal,
};

/// Split `raw_path` on `/` FIRST, then percent-decode each segment exactly
/// once into `buf`. Empty segments collapse (`//`, leading and trailing `/`).
/// Refused outright: an invalid %-escape; a decoded segment that is not valid
/// UTF-8 (overlong forms and surrogate halves included); a decoded C0 byte,
/// DEL, or C1 control codepoint; a decoded `.` or `..` segment; a segment over
/// 255 bytes; more than 32 segments. There is NO second decode pass, ever:
/// `%252F` decodes to the three literal bytes `%2F` and stays data.
pub fn canonicalize(raw_path: []const u8, buf: []u8, segs: [][]const u8) PathResult {
	std.debug.assert(segs.len >= max_segments);
	if (raw_path.len > 0 and raw_path[0] != '/') return .{ .refuse = .not_origin_form };

	var n: usize = 0;
	var used: usize = 0;
	var it = std.mem.splitScalar(u8, raw_path, '/');
	while (it.next()) |raw_seg| {
		if (raw_seg.len == 0) continue; // collapse: an empty segment names nothing
		const dec = decodeOnce(raw_seg, buf[used..]) orelse return .{ .refuse = .invalid_escape };
		if (dec.len > max_segment_len) return .{ .refuse = .segment_too_long };
		if (!std.unicode.utf8ValidateSlice(dec)) return .{ .refuse = .invalid_utf8 };
		if (hasControlByte(dec)) return .{ .refuse = .bad_byte };
		// A `.` or `..` PATH COMPONENT of the decoded segment is REFUSED. The
		// check is over the decoded segment split on `/`, not just the whole
		// segment equal to `..`, because segment-first decoding turns
		// `..%2F..%2Faccess_tokens` into ONE segment whose value is
		// `../../access_tokens` -- and GitLab's origin router DECODES `%2F` and
		// normalizes `..`, so forwarding it re-encoded would let the request be
		// authorized as one resource (an issues subtree) and routed by the
		// origin as another (a token mint). This is the whole reason the shared
		// table's `reject` rows must still deny in the route engine. `grp%2Fproj`
		// survives: its components (grp, proj) are ordinary data.
		if (hasDotComponent(dec)) return .{ .refuse = .dot_segment };
		if (n >= max_segments) return .{ .refuse = .too_many_segments };
		segs[n] = dec;
		n += 1;
		used += dec.len;
	}
	return .{ .ok = n };
}

/// Percent-decode one raw slice into `out`. Exactly one pass. Returns null on
/// an invalid escape (`%` not followed by two hex digits) or overflow -- unlike
/// the legacy normalizer, which passes a malformed escape through as literals.
/// Pub so a route's query-value validation (gitlab's `?service=`) decodes with
/// the SAME single-pass rules the path side uses.
pub fn decodeOnce(raw: []const u8, out: []u8) ?[]u8 {
	var o: usize = 0;
	var i: usize = 0;
	while (i < raw.len) {
		if (o >= out.len) return null;
		if (raw[i] == '%') {
			if (i + 2 >= raw.len or !isHex(raw[i + 1]) or !isHex(raw[i + 2])) return null;
			out[o] = (hexVal(raw[i + 1]) << 4) | hexVal(raw[i + 2]);
			i += 3;
		} else {
			out[o] = raw[i];
			i += 1;
		}
		o += 1;
	}
	return out[0..o];
}

/// True if any `/`-delimited component of a decoded segment is `.` or `..`.
fn hasDotComponent(s: []const u8) bool {
	var it = std.mem.splitScalar(u8, s, '/');
	while (it.next()) |comp| {
		if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return true;
	}
	return false;
}

/// C0 (NUL/CR/LF/tab included), DEL, or a C1 control codepoint. The C1 check is
/// byte-pair exact BECAUSE the caller has already validated UTF-8: U+0080..U+009F
/// encode as exactly 0xC2 0x80..0x9F, and no other valid sequence starts 0xC2.
fn hasControlByte(s: []const u8) bool {
	var i: usize = 0;
	while (i < s.len) : (i += 1) {
		const b = s[i];
		if (b < 0x20 or b == 0x7f) return true;
		if (b == 0xc2 and i + 1 < s.len and s[i + 1] <= 0x9f) return true;
	}
	return false;
}

fn isHex(ch: u8) bool {
	return (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F');
}
fn hexVal(ch: u8) u8 {
	if (ch >= '0' and ch <= '9') return ch - '0';
	if (ch >= 'a' and ch <= 'f') return ch - 'a' + 10;
	return ch - 'A' + 10;
}

/// GitLab's `:id` numeric form: `^[0-9]{1,19}$`, ASCII digits only, no sign, no
/// leading zero, compared as i64. Anything else (including a fullwidth or
/// Arabic-Indic digit, a sign, whitespace, or a 20-digit overflow) is NOT a
/// numeric id -- it may still be a path-form candidate, which authorization
/// then tests against grant paths and fails closed.
pub fn numericId(seg: []const u8) ?i64 {
	if (seg.len == 0 or seg.len > 19) return null;
	for (seg) |ch| {
		if (ch < '0' or ch > '9') return null;
	}
	if (seg.len > 1 and seg[0] == '0') return null;
	return std.fmt.parseInt(i64, seg, 10) catch null;
}

/// One parsed query parameter. The KEY is percent-decoded once (so `%73ervice`
/// cannot smuggle past a key match); the VALUE and the whole `k=v` pair are
/// kept RAW so a pass-through route re-emits exactly the bytes it received.
pub const QueryParam = struct {
	key: []const u8, // decoded once, points into the caller's key buffer
	value_raw: []const u8, // raw, undecoded
	raw: []const u8, // the whole raw `k[=v]` pair, for upstream re-emission
};

pub const QueryResult = union(enum) {
	ok: usize, // number of params written
	refuse: Refusal,
};

/// Parse a raw query string (without the `?`) into pairs. Keys are decoded
/// exactly once and refused on an invalid escape or any control byte; values
/// stay raw for re-emission but are VALIDATED by the same byte rules (decoded
/// once into scratch, refused on an invalid escape, a C0/C1/DEL byte or
/// invalid UTF-8): a pass-through route re-emits `raw` into the constructed
/// upstream request line, so a raw CR there is header injection at the
/// origin, and a value that DECODES to one has no legitimate API use. Over
/// `max_query_params` pairs is refused, fail closed.
pub fn parseQuery(raw_query: []const u8, key_buf: []u8, params: []QueryParam) QueryResult {
	std.debug.assert(params.len >= max_query_params);
	var n: usize = 0;
	var used: usize = 0;
	var it = std.mem.splitScalar(u8, raw_query, '&');
	while (it.next()) |pair| {
		if (pair.len == 0) continue;
		const eq = std.mem.indexOfScalar(u8, pair, '=');
		const raw_key = if (eq) |e| pair[0..e] else pair;
		const raw_val = if (eq) |e| pair[e + 1 ..] else "";
		const key = decodeOnce(raw_key, key_buf[used..]) orelse return .{ .refuse = .query_invalid };
		if (hasControlByte(key) or !std.unicode.utf8ValidateSlice(key)) return .{ .refuse = .query_invalid };
		if (!queryValueClean(raw_val)) return .{ .refuse = .query_invalid };
		if (n >= max_query_params) return .{ .refuse = .query_too_many };
		params[n] = .{ .key = key, .value_raw = raw_val, .raw = pair };
		n += 1;
		used += key.len;
	}
	return .{ .ok = n };
}

/// A query VALUE passes iff its raw bytes carry no control byte and it decodes
/// (once) to bytes that are valid UTF-8 with no C0/C1/DEL. The decoded form is
/// scratch only -- the raw form is what a pass-through route re-emits.
fn queryValueClean(raw_val: []const u8) bool {
	if (hasControlByte(raw_val)) return false;
	// A value cannot exceed the request line it arrived in (8 KiB), so a fixed
	// scratch decode is exact; anything longer is refused with the overflow.
	var scratch: [8 * 1024]u8 = undefined;
	const dec = decodeOnce(raw_val, &scratch) orelse return false;
	return std.unicode.utf8ValidateSlice(dec) and !hasControlByte(dec);
}

/// Credential-bearing / method-override query keys, refused outright on every
/// route (spec §7): a provider accepting `?private_token=` means an allowed
/// request could carry a credential we never vetted, and `_method` is the
/// query twin of the stripped override headers.
pub fn forbiddenQueryKey(key: []const u8) bool {
	const forbidden = [_][]const u8{ "private_token", "access_token", "job_token", "_method" };
	for (forbidden) |f| {
		if (std.ascii.eqlIgnoreCase(key, f)) return true;
	}
	return false;
}

// --- Tests ---

const t = std.testing;

fn canonOk(raw: []const u8, want: []const []const u8) !void {
	var buf: [8192]u8 = undefined;
	var segs: [max_segments][]const u8 = undefined;
	const r = canonicalize(raw, &buf, &segs);
	try t.expect(r == .ok);
	try t.expectEqual(want.len, r.ok);
	for (want, 0..) |w, i| try t.expectEqualStrings(w, segs[i]);
}

fn canonRefused(raw: []const u8, want: Refusal) !void {
	var buf: [8192]u8 = undefined;
	var segs: [max_segments][]const u8 = undefined;
	const r = canonicalize(raw, &buf, &segs);
	try t.expect(r == .refuse);
	try t.expectEqual(want, r.refuse);
}

test "canonicalize: segment-first single decode keeps %2F inside ONE segment" {
	// The inverted oracle vs path_vectors.tsv:62-64: the legacy normalizer
	// INFLATES `grp%2Fproj` into extra segments; this engine must not.
	try canonOk("/api/v4/projects/grp%2Fproj", &.{ "api", "v4", "projects", "grp/proj" });
	try canonOk("/api/v4/projects/grp%2fproj/issues", &.{ "api", "v4", "projects", "grp/proj", "issues" });
	try canonOk("/api/v4/projects/a%2Fb%2Fc/access_tokens", &.{ "api", "v4", "projects", "a/b/c", "access_tokens" });
	// Single-pass: %252F -> the literal bytes `%2F`, never re-decoded.
	try canonOk("/api/v4/projects/grp%252Fproj", &.{ "api", "v4", "projects", "grp%2Fproj" });
}

test "canonicalize: empty segments collapse, fragment handling is the caller's" {
	try canonOk("//a", &.{"a"});
	try canonOk("/a//b//", &.{ "a", "b" });
	try canonOk("/", &.{});
	try canonOk("", &.{});
	try canonOk("/%61dmin/x", &.{ "admin", "x" });
	// Dots INSIDE a segment are ordinary data.
	try canonOk("/a/..b/c...", &.{ "a", "..b", "c..." });
	// A literal `*` or `#` (the fragment split happens in splitTarget) is data.
	try canonOk("/a/*/b", &.{ "a", "*", "b" });
	try canonOk("/a/%2A/b", &.{ "a", "*", "b" });
	try canonOk("/a/%23/b", &.{ "a", "#", "b" });
}

test "canonicalize: dot segments refused in every form" {
	try canonRefused("/api/../%61dmin/./x", .dot_segment);
	try canonRefused("/v1/%2e%2e/secret", .dot_segment);
	try canonRefused("/../..", .dot_segment);
	try canonRefused("/a/./b", .dot_segment);
	try canonRefused("/api/v4/projects/1234/issues/..%2F..%2Faccess_tokens", .dot_segment);
}

test "canonicalize: byte-level refusals" {
	try canonRefused("/a/%C0%AF/b", .invalid_utf8); // overlong 2-byte
	try canonRefused("/a/%E0%80%AF/b", .invalid_utf8); // overlong 3-byte
	try canonRefused("/a/%ED%A0%80/b", .invalid_utf8); // lone surrogate
	try canonRefused("/a/%00/b", .bad_byte);
	try canonRefused("/a/x%0D%0Ay/b", .bad_byte);
	try canonRefused("/a/%09/b", .bad_byte); // tab
	try canonRefused("/a/%C2%85/b", .bad_byte); // C1 NEL
	try canonRefused("/a/%zz/b", .invalid_escape);
	try canonRefused("/a/50%/b", .invalid_escape); // trailing bare %
	try canonRefused("/a/%2/b", .invalid_escape);
	try canonRefused("relative/path", .not_origin_form);
}

test "canonicalize: size caps" {
	var long: [300]u8 = @splat('a');
	var buf: [1024]u8 = undefined;
	const raw = try std.fmt.bufPrint(&buf, "/{s}", .{long[0..256]});
	try canonRefused(raw, .segment_too_long);
	// exactly 255 is fine
	const raw255 = try std.fmt.bufPrint(&buf, "/{s}", .{long[0..255]});
	var dbuf: [8192]u8 = undefined;
	var segs: [max_segments][]const u8 = undefined;
	try t.expect(canonicalize(raw255, &dbuf, &segs) == .ok);
	// 33 segments refused, 32 accepted
	var pbuf: [256]u8 = undefined;
	var w: usize = 0;
	for (0..33) |_| {
		pbuf[w] = '/';
		pbuf[w + 1] = 'x';
		w += 2;
	}
	try canonRefused(pbuf[0..w], .too_many_segments);
	try t.expect(canonicalize(pbuf[0 .. w - 2], &dbuf, &segs) == .ok);
}

test "numericId: ASCII digits only, no sign, no leading zero, i64 range" {
	try t.expectEqual(@as(?i64, 1234), numericId("1234"));
	try t.expectEqual(@as(?i64, 0), numericId("0"));
	try t.expectEqual(@as(?i64, 1234567890123456789), numericId("1234567890123456789")); // 19 digits
	try t.expectEqual(@as(?i64, null), numericId("01234")); // leading zero
	try t.expectEqual(@as(?i64, null), numericId("+1234")); // sign
	try t.expectEqual(@as(?i64, null), numericId("1234 ")); // trailing space
	try t.expectEqual(@as(?i64, null), numericId("１２３４")); // fullwidth digits
	try t.expectEqual(@as(?i64, null), numericId("12345678901234567890")); // 20 digits
	try t.expectEqual(@as(?i64, null), numericId("9999999999999999999")); // 19 digits, > maxInt(i64)
	try t.expectEqual(@as(?i64, null), numericId(""));
	try t.expectEqual(@as(?i64, null), numericId("12a4"));
	try t.expectEqual(@as(?i64, null), numericId("1234/issues"));
}

test "splitTarget: fragment stripped with everything after it, query split once" {
	try t.expectEqualStrings("/v1/x", splitTarget("/v1/x?q=1").path);
	try t.expectEqualStrings("q=1", splitTarget("/v1/x?q=1").query);
	try t.expectEqualStrings("/v1/x", splitTarget("/v1/x#frag").path);
	try t.expectEqualStrings("", splitTarget("/v1/x#frag").query);
	// a raw `#` is a FRAGMENT delimiter even before any `?`
	try t.expectEqualStrings("/a/", splitTarget("/a/#/b").path);
	try t.expectEqualStrings("/a/x", splitTarget("/a/x?q=1#frag").path);
	try t.expectEqualStrings("q=1", splitTarget("/a/x?q=1#frag").query);
	// fragment before the ? swallows the query too
	try t.expectEqualStrings("", splitTarget("/a#f?q=1").query);
}

test "parseQuery: keys decoded once, values raw, forbidden keys named" {
	var kb: [512]u8 = undefined;
	var ps: [max_query_params]QueryParam = undefined;
	const r = parseQuery("service=git-upload-pack&%73neaky=1&b=%2F", &kb, &ps);
	try t.expect(r == .ok);
	try t.expectEqual(@as(usize, 3), r.ok);
	try t.expectEqualStrings("service", ps[0].key);
	try t.expectEqualStrings("git-upload-pack", ps[0].value_raw);
	try t.expectEqualStrings("sneaky", ps[1].key); // key decoded exactly once
	try t.expectEqualStrings("b=%2F", ps[2].raw); // value stays raw
	try t.expect(forbiddenQueryKey("private_token"));
	try t.expect(forbiddenQueryKey("Access_Token"));
	try t.expect(forbiddenQueryKey("job_token"));
	try t.expect(forbiddenQueryKey("_method"));
	try t.expect(!forbiddenQueryKey("service"));
	// %5Fmethod decodes to _method -> the key match cannot be smuggled past
	const r2 = parseQuery("%5Fmethod=DELETE", &kb, &ps);
	try t.expect(r2 == .ok);
	try t.expect(forbiddenQueryKey(ps[0].key));
}

test "parseQuery: values are validated by the key's byte rules, re-emitted raw (S7)" {
	var kb: [512]u8 = undefined;
	var ps: [max_query_params]QueryParam = undefined;
	// a RAW lone CR in a value: the constructed request line would carry it
	try t.expectEqual(Refusal.query_invalid, parseQuery("a=b\rc", &kb, &ps).refuse);
	try t.expectEqual(Refusal.query_invalid, parseQuery("a=b\nc", &kb, &ps).refuse);
	try t.expectEqual(Refusal.query_invalid, parseQuery("a=b\x00c", &kb, &ps).refuse);
	// a value that DECODES to a control byte / invalid UTF-8 / a bad escape
	try t.expectEqual(Refusal.query_invalid, parseQuery("a=b%0Dc", &kb, &ps).refuse);
	try t.expectEqual(Refusal.query_invalid, parseQuery("a=%C0%AF", &kb, &ps).refuse);
	try t.expectEqual(Refusal.query_invalid, parseQuery("a=100%", &kb, &ps).refuse);
	// ordinary encoded data passes and stays RAW
	const r = parseQuery("search=caf%C3%A9%20x&b=%2F", &kb, &ps);
	try t.expect(r == .ok);
	try t.expectEqualStrings("caf%C3%A9%20x", ps[0].value_raw);
	try t.expectEqualStrings("b=%2F", ps[1].raw);
}

test "parseQuery: refusals" {
	var kb: [512]u8 = undefined;
	var ps: [max_query_params]QueryParam = undefined;
	try t.expect(parseQuery("a%zz=1", &kb, &ps) == .refuse);
	var big: [4096]u8 = undefined;
	var w: usize = 0;
	for (0..65) |i| {
		const p = std.fmt.bufPrint(big[w..], "k{d}=1&", .{i}) catch unreachable;
		w += p.len;
	}
	const r = parseQuery(big[0 .. w - 1], &kb, &ps);
	try t.expect(r == .refuse);
	try t.expectEqual(Refusal.query_too_many, r.refuse);
}
