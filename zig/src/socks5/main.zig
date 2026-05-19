// Minimal synchronous SOCKS5 v5 CONNECT client. The shim drives this
// over the fd it just connected to a SOCKS5-speaking proxy, carrying the
// original destination (IP, port) as the CONNECT target. Only the
// no-auth (METHOD 0) variant is implemented -- the proxy we ship runs
// on loopback and isn't reachable from anywhere else.
//
// Designed to be safe to call from inside the LD_PRELOAD shim: no
// allocator, fixed-size stack buffers, raw read/write via libc only.

const std = @import("std");
const filter = @import("filter");

pub const Error = error{
	AuthMethodRejected,
	ConnectRejected,
	ProtocolError,
	Truncated,
	IoError,
};

extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;

fn writeAll(fd: c_int, buf: []const u8) Error!void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = write(fd, buf.ptr + off, buf.len - off);
		if (n <= 0) return error.IoError;
		off += @intCast(n);
	}
}

fn readExact(fd: c_int, buf: []u8) Error!void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = read(fd, buf.ptr + off, buf.len - off);
		if (n < 0) return error.IoError;
		if (n == 0) return error.Truncated;
		off += @intCast(n);
	}
}

/// Perform a SOCKS5 v5 CONNECT handshake on `fd` (which must already be
/// connected to a SOCKS5 server). On success the fd is in passthrough
/// mode: subsequent reads/writes flow to/from the original destination.
pub fn handshake(fd: c_int, target_addr: filter.IpAddr, target_port: u16) Error!void {
	// Greeting: VER=5, NMETHODS=1, METHODS=[0 (no auth)]
	try writeAll(fd, &.{ 0x05, 0x01, 0x00 });

	// Server method selection: VER, METHOD
	var sel: [2]u8 = undefined;
	try readExact(fd, &sel);
	if (sel[0] != 0x05) return error.ProtocolError;
	if (sel[1] != 0x00) return error.AuthMethodRejected;

	// CONNECT request: VER=5, CMD=1, RSV=0, ATYP, ADDR, PORT(big-endian)
	var req: [22]u8 = undefined;
	req[0] = 0x05;
	req[1] = 0x01;
	req[2] = 0x00;
	var req_len: usize = 4;
	switch (target_addr) {
		.ipv4 => |ip| {
			req[3] = 0x01;
			@memcpy(req[4..8], &ip);
			req_len = 8;
		},
		.ipv6 => |ip| {
			req[3] = 0x04;
			@memcpy(req[4..20], &ip);
			req_len = 20;
		},
	}
	req[req_len] = @intCast((target_port >> 8) & 0xff);
	req[req_len + 1] = @intCast(target_port & 0xff);
	req_len += 2;
	try writeAll(fd, req[0..req_len]);

	// Server reply: VER, REP, RSV, ATYP, BIND_ADDR, BIND_PORT
	var head: [4]u8 = undefined;
	try readExact(fd, &head);
	if (head[0] != 0x05) return error.ProtocolError;
	if (head[1] != 0x00) return error.ConnectRejected;
	const tail_len: usize = switch (head[3]) {
		0x01 => 4 + 2,
		0x04 => 16 + 2,
		0x03 => blk: {
			var lb: [1]u8 = undefined;
			try readExact(fd, &lb);
			break :blk @as(usize, lb[0]) + 2;
		},
		else => return error.ProtocolError,
	};
	var tail: [256 + 2]u8 = undefined;
	if (tail_len > tail.len) return error.ProtocolError;
	try readExact(fd, tail[0..tail_len]);
}

// --- Tests ---

const t = std.testing;

extern "c" fn socketpair(domain: c_int, type_: c_int, proto_: c_int, sv: *[2]c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SHUT_WR: c_int = 1;

fn newPair() ![2]c_int {
	var sv: [2]c_int = undefined;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) != 0) return error.IoError;
	return sv;
}

test "handshake ipv4 success" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	// Pre-stage server replies on sv[1]; handshake reads them on sv[0].
	try writeAll(sv[1], &.{ 0x05, 0x00 });
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

	try handshake(sv[0], .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443);

	// Inspect what handshake wrote into sv[0]; readable on sv[1].
	var got: [13]u8 = undefined;
	try readExact(sv[1], &got);

	const expected = [_]u8{
		0x05, 0x01, 0x00, // greeting
		0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb, // connect 1.2.3.4:443
	};
	try t.expectEqualSlices(u8, &expected, &got);
}

test "handshake ipv6 success" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0x00 });
	// Reply with ipv4 BIND form (server's choice; client doesn't care)
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

	const v6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	try handshake(sv[0], .{ .ipv6 = v6 }, 80);

	var got: [25]u8 = undefined;
	try readExact(sv[1], &got);
	try t.expectEqualSlices(u8, &.{ 0x05, 0x01, 0x00 }, got[0..3]); // greeting
	try t.expectEqual(@as(u8, 0x04), got[6]); // ATYP=ipv6
	try t.expectEqualSlices(u8, &v6, got[7..23]);
	try t.expectEqual(@as(u16, 80), std.mem.readInt(u16, got[23..25], .big));
}

test "handshake rejects when server picks unknown auth method" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0xff }); // METHOD = NO ACCEPTABLE METHODS

	try t.expectError(error.AuthMethodRejected, handshake(sv[0], .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "handshake reports connect rejected on non-zero REP" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0x00 });
	// REP=0x05 (connection refused), ATYP=ipv4, junk addr/port
	try writeAll(sv[1], &.{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

	try t.expectError(error.ConnectRejected, handshake(sv[0], .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "handshake reports protocol error on wrong server version" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x04, 0x00 }); // wrong VER

	try t.expectError(error.ProtocolError, handshake(sv[0], .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "handshake reports truncated when server EOFs mid-reply" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0x00 });
	// Only write 3 bytes of the connect reply, then half-close the
	// write side so the client gets EOF mid-read but its own writes to
	// the peer still go through.
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00 });
	_ = shutdown(sv[1], SHUT_WR);

	try t.expectError(error.Truncated, handshake(sv[0], .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}
