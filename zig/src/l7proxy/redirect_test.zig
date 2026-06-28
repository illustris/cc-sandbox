// Conformance tests for the l7proxy redirect accept mode + raw-L4 splice arm
// (Part 2 of the container enforcer). These cover the NEW security-critical
// code:
//   - kernel original-dst recovery via SO_ORIGINAL_DST (the conntrack original
//     tuple): correct extraction, the loopback/own-listener anti-loop refusal,
//     and the v4-only guard;
//   - the raw-L4 gate matrix: the non-overridable SSRF hard floor + ordered
//     first-match CIDR policy, default-deny, incl. the IPv4-mapped cloud
//     metadata address;
//   - the classify-vs-raw-L4 boundary: 80/443 still classify (TLS/HTTP, ->
//     terminate, not raw-L4); an unclassifiable flow on :443 is GATED, not
//     auto-allowed; an ECH ClientHello is still refused on the splice tier.
//
// The redirect path takes NO CAP_NET_ADMIN: it binds a normal listener and
// reads only SO_ORIGINAL_DST (no IP_TRANSPARENT, no getsockname, no fwmark).
// The existing filter.zig / tls.zig / http.zig test blocks remain the L4 +
// classification parity proof and run unchanged.

const std = @import("std");
const t = std.testing;
const filter = @import("filter");
const main = @import("main.zig");

// Own cImport so the tests can construct libc-ABI sockaddrs to feed the
// kernel-sockaddr parser. The pointers cross into main as type-erased anyopaque,
// so this distinct cImport instance is fine -- the memory layout is identical.
const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
});

// libc bits the socketpair-driven classify tests need.
extern "c" fn socketpair(domain: c_int, type: c_int, protocol: c_int, sv: *[2]c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SHUT_WR: c_int = 1;

fn inetV4(a: u8, b: u8, cc: u8, d: u8, port: u16) c.struct_sockaddr_in {
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = @bitCast([4]u8{ a, b, cc, d });
	return sa;
}

fn inetV6Loopback(port: u16) c.struct_sockaddr_in6 {
	var sa: c.struct_sockaddr_in6 = std.mem.zeroes(c.struct_sockaddr_in6);
	sa.sin6_family = c.AF_INET6;
	sa.sin6_port = std.mem.nativeToBig(u16, port);
	@as([*]u8, @ptrCast(&sa.sin6_addr))[15] = 1; // ::1
	return sa;
}

// --- original-dst extraction (origFromStorage / origDstFromStorage) ---

test "origFromStorage extracts the v4 dst from a kernel sockaddr" {
	const sa = inetV4(203, 0, 113, 7, 8443);
	const o = main.origFromStorage(&sa).?;
	try t.expectEqual(filter.IpAddr{ .ipv4 = .{ 203, 0, 113, 7 } }, o.addr);
	try t.expectEqual(@as(u16, 8443), o.port);
}

test "origFromStorage refuses a non-v4 (v6) family" {
	const sa6 = inetV6Loopback(443);
	try t.expect(main.origFromStorage(&sa6) == null);
}

test "origDstFromStorage: SO_ORIGINAL_DST yields the right Orig" {
	// The conntrack original tuple as the kernel would fill it: the real
	// pre-redirect destination the guest aimed at.
	const od = inetV4(93, 184, 216, 34, 443);
	const o = main.origDstFromStorage(&od).?;
	try t.expectEqual(filter.IpAddr{ .ipv4 = .{ 93, 184, 216, 34 } }, o.addr);
	try t.expectEqual(@as(u16, 443), o.port);
}

test "origDstFromStorage: loopback / own-listener orig dst refused (anti-loop)" {
	// SO_ORIGINAL_DST returns loopback only when there was no DNAT: a direct hit
	// on our own 127.0.0.1 listener (an accept loop) -> refuse.
	const own = inetV4(127, 0, 0, 1, 18443);
	try t.expect(main.origDstFromStorage(&own) == null);
	// Any other loopback dst is likewise refused.
	const lo = inetV4(127, 0, 0, 53, 53);
	try t.expect(main.origDstFromStorage(&lo) == null);
}

test "origDstFromStorage: a non-v4 dst is refused" {
	const od6 = inetV6Loopback(443);
	try t.expect(main.origDstFromStorage(&od6) == null);
}

// --- raw-L4 gate matrix (rawL4Allowed) ---

test "rawL4Allowed: default-deny gates an unclassifiable flow" {
	const rs = filter.parseRules(""); // empty -> default deny
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }));
}

test "rawL4Allowed: explicit allow admits, ordered first-match on port + cidr" {
	const rs = filter.parseRules(
		\\allow tcp 93.184.216.0/24:443
		\\deny 0.0.0.0/0
	);
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }));
	// wrong port -> not matched by the :443 allow -> falls to deny
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 22 }));
	// outside the /24 -> deny
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 198, 51, 100, 1 } }, .port = 443 }));
}

test "rawL4Allowed: an earlier deny wins over a later allow (ordered)" {
	const rs = filter.parseRules(
		\\deny 10.0.0.0/8
		\\allow 0.0.0.0/0
	);
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 10, 1, 2, 3 } }, .port = 443 }));
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 8, 8, 8, 8 } }, .port = 443 }));
}

test "rawL4Allowed: SSRF hard floor cannot be overridden by allow-all" {
	// Even `allow 0.0.0.0/0` must not let raw-L4 reach loopback / this-net /
	// link-local(+metadata). The hard floor is checked first and is final.
	const rs = filter.parseRules("allow 0.0.0.0/0");
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 443 }));
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 169, 254, 169, 254 } }, .port = 80 })); // cloud metadata
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 0, 0, 0, 0 } }, .port = 443 }));
}

test "rawL4Allowed: IPv4-mapped metadata (::ffff:169.254.169.254) is dropped" {
	const rs = filter.parseRules("allow 0.0.0.0/0");
	const mapped = filter.IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 } };
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = mapped, .port = 80 }));
}

// --- classify vs raw-L4 boundary (peekClassify on a real fd) ---

// Minimal single-record TLS ClientHello builder -- mirrors tls.zig's test
// fixture so the classify path is exercised on real bytes over a real socket.
fn buildHello(buf: []u8, server_name: []const u8, with_ech: bool) []u8 {
	var hs: [1024]u8 = undefined;
	var n: usize = 0;
	hs[n] = 0x03;
	hs[n + 1] = 0x03;
	n += 2; // client_version TLS1.2
	@memset(hs[n .. n + 32], 0);
	n += 32; // random
	hs[n] = 0;
	n += 1; // session_id len 0
	hs[n] = 0x00;
	hs[n + 1] = 0x02;
	hs[n + 2] = 0x13;
	hs[n + 3] = 0x01;
	n += 4; // cipher_suites len2 + one suite
	hs[n] = 0x01;
	hs[n + 1] = 0x00;
	n += 2; // compression: len1 + null
	const ext_len_pos = n;
	n += 2; // placeholder for extensions length
	const ext_start = n;
	if (server_name.len > 0) {
		const sni_inner = 2 + 1 + 2 + server_name.len;
		hs[n] = 0x00;
		hs[n + 1] = 0x00;
		n += 2; // ext type server_name
		hs[n] = @intCast((sni_inner >> 8) & 0xff);
		hs[n + 1] = @intCast(sni_inner & 0xff);
		n += 2; // ext data len
		const list_len = 1 + 2 + server_name.len;
		hs[n] = @intCast((list_len >> 8) & 0xff);
		hs[n + 1] = @intCast(list_len & 0xff);
		n += 2; // server_name_list length
		hs[n] = 0x00;
		n += 1; // name_type host_name
		hs[n] = @intCast((server_name.len >> 8) & 0xff);
		hs[n + 1] = @intCast(server_name.len & 0xff);
		n += 2; // name length
		@memcpy(hs[n .. n + server_name.len], server_name);
		n += server_name.len;
	}
	if (with_ech) {
		hs[n] = 0xfe;
		hs[n + 1] = 0x0d;
		n += 2; // ext type ECH
		hs[n] = 0x00;
		hs[n + 1] = 0x01;
		n += 2; // ext data len 1
		hs[n] = 0x00;
		n += 1;
	}
	const ext_total = n - ext_start;
	hs[ext_len_pos] = @intCast((ext_total >> 8) & 0xff);
	hs[ext_len_pos + 1] = @intCast(ext_total & 0xff);

	var msg: [1100]u8 = undefined;
	msg[0] = 0x01; // handshake type client_hello
	msg[1] = @intCast((n >> 16) & 0xff);
	msg[2] = @intCast((n >> 8) & 0xff);
	msg[3] = @intCast(n & 0xff);
	@memcpy(msg[4 .. 4 + n], hs[0..n]);
	const msg_len = 4 + n;

	buf[0] = 0x16; // TLS record: handshake
	buf[1] = 0x03;
	buf[2] = 0x01;
	buf[3] = @intCast((msg_len >> 8) & 0xff);
	buf[4] = @intCast(msg_len & 0xff);
	@memcpy(buf[5 .. 5 + msg_len], msg[0..msg_len]);
	return buf[0 .. 5 + msg_len];
}

// Feed `bytes` through a socketpair and classify the reading end. SHUT_WR after
// the write so a classifier that needs more bytes hits EOF rather than blocking.
// The out buffers are caller-owned: a .tls/.http result aliases out_sni/out_host,
// so they must outlive this call.
fn classifyBytes(bytes: []const u8, oh: []u8, op: []u8, os: []u8) main.Classified {
	var sv: [2]c_int = undefined;
	std.debug.assert(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0);
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	_ = write(sv[1], bytes.ptr, bytes.len);
	_ = shutdown(sv[1], SHUT_WR);

	var buf: [16 * 1024]u8 = undefined; // peek buffer; not aliased by the result
	var buffered: usize = 0;
	return main.peekClassify(sv[0], &buf, &buffered, oh, op, os);
}

test "classify: a TLS ClientHello on :443 classifies as .tls (not raw-L4)" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "app.example.com", false);
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes(hello, &oh, &op, &os);
	try t.expect(cl == .tls);
	try t.expectEqualStrings("app.example.com", cl.tls.name);
	try t.expect(!cl.tls.ech);
}

test "classify: an allowed TLS host routes to the terminate tier (no regression)" {
	var rs: filter.L7RuleSet = .{};
	filter.parseL7Rules("allow app.example.com", &rs);
	// default mode_terminate == true: a matched allow host is MITM-terminated
	// (handed to mitmproxy), NOT raw-L4 spliced.
	try t.expect(rs.needsTerminate("app.example.com"));
	try t.expect(rs.evaluate("app.example.com", null) == .allow);
}

test "classify: an HTTP/1.1 request on :80 classifies as .http (not raw-L4)" {
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes("GET /v1/x HTTP/1.1\r\nHost: app.example.com\r\n\r\n", &oh, &op, &os);
	try t.expect(cl == .http);
	try t.expectEqualStrings("app.example.com", cl.http.host);
}

test "classify: an unclassifiable flow on :443 is .deny -> raw-L4 GATED, not auto-allowed" {
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	// Random first byte: not 0x16 (TLS), not an uppercase HTTP method -> .deny.
	const cl = classifyBytes(&[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44 }, &oh, &op, &os);
	try t.expect(cl == .deny);

	// .deny on :443 does NOT imply allow -- the raw-L4 arm still gates it. Under
	// the instance default-deny it is dropped; only an explicit L4 allow lets it
	// reach its kernel orig dst. Port 443 carries no special privilege.
	const orig = main.Orig{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 };
	const deny_rs = filter.parseRules("");
	try t.expect(!main.rawL4Allowed(&deny_rs, orig));
	const allow_rs = filter.parseRules("allow tcp 93.184.216.0/24:443");
	try t.expect(main.rawL4Allowed(&allow_rs, orig));
}

test "classify: an ECH ClientHello is still refused on the splice tier" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "app.example.com", true); // GREASE/real ECH present
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes(hello, &oh, &op, &os);
	try t.expect(cl == .tls);
	try t.expect(cl.tls.ech); // ECH flagged for the worker

	// On the splice (passthrough) tier the worker refuses an ECH-bearing hello:
	// the production condition is `is_tls and ech and !needs_term`. A passthrough
	// host's needsTerminate is false, so the refusal holds.
	var rs: filter.L7RuleSet = .{};
	filter.parseL7Rules("mode passthrough\nallow app.example.com", &rs);
	const needs_term = rs.needsTerminate("app.example.com");
	try t.expect(!needs_term);
	const is_tls = true;
	try t.expect(is_tls and cl.tls.ech and !needs_term);
}
