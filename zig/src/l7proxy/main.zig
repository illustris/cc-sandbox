// cogbox __l7proxy <runtime-dir>
//
// Host-side L7 proxy. The guest's 80/443 egress is funneled here by the
// netfilter shim's remap (a SOCKS5 CONNECT carrying the ORIGINAL ip:port).
// We accept the SOCKS5 connection, peek the first app bytes to learn the
// vhost (TLS SNI or HTTP Host), evaluate it against the L7 rules, then
// RE-RESOLVE that name host-side and splice -- never trusting the guest's
// chosen IP. Every re-resolved address is vetted against a non-overridable
// SSRF floor AND the instance's own CIDR deny-list before we connect.
//
// Runs as a normal host process (NOT under the LD_PRELOAD shim), so its own
// getaddrinfo()+connect() reach the real internet -- which is exactly why
// the SSRF/CIDR re-check below is mandatory.
//
// Phase 1 implements the passthrough tier (no TLS termination). A host that
// needs termination (path rules / Host==SNI) is denied here until Phase 2.

const std = @import("std");
const filter = @import("filter");
const tls = @import("tls.zig");
const http = @import("http.zig");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	// Disable glibc FORTIFY: in ReleaseSafe, translate-c renders the checked
	// inline wrappers (__poll_chk / __recv_chk ...) with an object_size() call
	// whose FORTIFY-level argument comes out as bool, which fails to compile.
	// We don't want the checked variants anyway.
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("netdb.h");
	@cInclude("sys/time.h");
	@cInclude("poll.h");
	@cInclude("unistd.h");
	@cInclude("errno.h");
	@cInclude("string.h");
});

// open(2) -- declared directly to dodge fcntl.h's FORTIFY macros (same
// reasoning as the netfilter shim).
const O_RDONLY: c_int = 0;
extern "c" fn @"open"(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

// bind/connect/accept take glibc's transparent `__SOCKADDR_ARG` union through
// @cImport, which Zig can't pass a plain pointer to. Bind the raw libc symbols
// with sane sockaddr-pointer signatures instead.
const c_bind = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "bind" });
const c_connect = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "connect" });
const c_accept = @extern(*const fn (c_int, ?*c.struct_sockaddr, ?*c.socklen_t) callconv(.c) c_int, .{ .name = "accept" });

const peek_cap: usize = 16 * 1024;
const relay_buf: usize = 32 * 1024;
const io_timeout_secs: i32 = 15;
const relay_idle_ms: c_int = 120_000;
const max_conns: usize = 512;

// --- shared state ---
var runtime_dir_buf: [4096]u8 = undefined;
var runtime_dir_len: usize = 0;

// Loopback port of this instance's mitmproxy terminate backend (base + 2),
// set in run() from the instance's L7 port base.
var mitm_port: u16 = filter.l7_default_base + 2;

// Tiny test-and-set spinlock guarding the two rulesets. Critical sections are
// microsecond-short memory scans; reloads (the only writer, in the accept
// thread) are rare, so spinning is cheaper than a futex.
var rules_lock = std.atomic.Value(bool).init(false);
var cidr_rs: filter.RuleSet = .{};
var l7_rs: filter.L7RuleSet = .{};

fn lockRules() void {
	while (rules_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}
fn unlockRules() void {
	rules_lock.store(false, .release);
}

var reload_pending = std.atomic.Value(bool).init(false);
var conn_count = std.atomic.Value(usize).init(0);

pub fn run(_: std.mem.Allocator, runtime_dir: []const u8, l7_base: u16) !void {
	if (runtime_dir.len >= runtime_dir_buf.len) return error.PathTooLong;
	@memcpy(runtime_dir_buf[0..runtime_dir.len], runtime_dir);
	runtime_dir_len = runtime_dir.len;

	installSignals();
	loadRules();

	// Per-instance loopback ports (base / base+1 / base+2). Binding is
	// fail-closed: if a port is already taken (e.g. another instance picked
	// the same base, or a stale proxy), listenLoopback returns error.Bind and
	// the process exits non-zero -- the launcher treats that as a hard failure
	// and aborts the start rather than leaving the funnel pointed elsewhere.
	const ports = filter.l7PortsForBase(l7_base);
	mitm_port = ports.mitm;
	const tls_fd = try listenLoopback(ports.tls);
	const http_fd = try listenLoopback(ports.http);

	logLine("l7proxy: listening on 127.0.0.1:{d} (tls) :{d} (http); terminate backend :{d}", .{ ports.tls, ports.http, ports.mitm });

	const th = try std.Thread.spawn(.{}, acceptLoop, .{http_fd});
	th.detach();
	acceptLoop(tls_fd);
}

// --- signals / reload ---

fn onReloadSignal(_: std.posix.SIG) callconv(.c) void {
	reload_pending.store(true, .release);
}

fn installSignals() void {
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = onReloadSignal;
	std.posix.sigaction(std.posix.SIG.HUP, &act, null);
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);
}

fn loadRules() void {
	const rt = runtime_dir_buf[0..runtime_dir_len];
	var nf_buf: [16384]u8 = undefined;
	var l7_buf: [16384]u8 = undefined;
	const nf = readFileInto(rt, "netfilter-rules", &nf_buf);
	const l7 = readFileInto(rt, "l7-rules", &l7_buf);

	lockRules();
	defer unlockRules();
	cidr_rs = filter.parseRules(nf);
	filter.parseL7Rules(l7, &l7_rs);
}

fn readFileInto(rt: []const u8, name: []const u8, buf: []u8) []const u8 {
	var path_buf: [4096]u8 = undefined;
	const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ rt, name }) catch return buf[0..0];
	const fd = @"open"(path.ptr, O_RDONLY, 0);
	if (fd < 0) return buf[0..0];
	defer _ = c.close(fd);
	var total: usize = 0;
	while (total < buf.len) {
		const n = c.read(fd, @ptrCast(buf.ptr + total), buf.len - total);
		if (n <= 0) break;
		total += @intCast(n);
	}
	return buf[0..total];
}

// --- listener / accept ---

fn listenLoopback(port: u16) !c_int {
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return error.Socket;
	var one: c_int = 1;
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &one, @sizeOf(c_int));
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = std.mem.nativeToBig(u32, 0x7f000001); // 127.0.0.1
	if (c_bind(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) {
		_ = c.close(fd);
		return error.Bind;
	}
	if (c.listen(fd, 128) != 0) {
		_ = c.close(fd);
		return error.Listen;
	}
	return fd;
}

fn acceptLoop(listen_fd: c_int) void {
	var pfd = [_]c.struct_pollfd{.{ .fd = listen_fd, .events = c.POLLIN, .revents = 0 }};
	while (true) {
		if (reload_pending.swap(false, .acq_rel)) loadRules();
		const pr = c.poll(&pfd, 1, 1000);
		if (pr <= 0) continue;
		if ((pfd[0].revents & c.POLLIN) == 0) continue;
		const cfd = c_accept(listen_fd, null, null);
		if (cfd < 0) continue;
		if (conn_count.fetchAdd(1, .monotonic) >= max_conns) {
			_ = conn_count.fetchSub(1, .monotonic);
			_ = c.close(cfd);
			continue;
		}
		const th = std.Thread.spawn(.{}, worker, .{cfd}) catch {
			_ = conn_count.fetchSub(1, .monotonic);
			_ = c.close(cfd);
			continue;
		};
		th.detach();
	}
}

// --- per-connection worker ---

const Orig = struct { addr: filter.IpAddr, port: u16 };

const Classified = union(enum) {
	tls: []const u8, // SNI
	http: http.Parsed,
	deny,
};

fn worker(client_fd: c_int) void {
	defer _ = c.close(client_fd);
	defer _ = conn_count.fetchSub(1, .monotonic);

	setTimeouts(client_fd);

	const orig = socks5Accept(client_fd) orelse return;

	var buf: [peek_cap]u8 = undefined;
	var out_host: [256]u8 = undefined;
	var out_path: [2048]u8 = undefined;
	var out_sni: [256]u8 = undefined;
	var buffered: usize = 0;
	const cl = peekClassify(client_fd, &buf, &buffered, &out_host, &out_path, &out_sni);

	var host: []const u8 = undefined;
	var path: ?[]const u8 = null;
	var is_tls = false;
	switch (cl) {
		.deny => {
			logReject(orig, "?", "unclassifiable-or-no-sni");
			return;
		},
		.tls => |s| {
			host = s;
			is_tls = true;
		},
		.http => |p| {
			host = p.host;
			path = p.path;
		},
	}
	if (!filter.isValidHostName(host)) {
		logReject(orig, host, "invalid-hostname");
		return;
	}

	lockRules();
	const needs_term = l7_rs.needsTerminate(host);
	const verdict = l7_rs.evaluate(host, path);
	unlockRules();

	if (is_tls and needs_term) {
		// Terminate tier: re-resolve + vet here (SSRF/CIDR stays authoritative
		// in this proxy), then hand the VETTED IP to the mitmproxy backend over
		// SOCKS5. mitmproxy mints a per-SNI leaf from the instance CA, decrypts,
		// and an addon enforces allow/deny + path + Host==SNI. The allow/deny
		// decision for terminate hosts is made there (it needs the path), not
		// here -- so we do NOT consult `action` on this branch.
		terminateHandoff(client_fd, host, orig, buf[0..buffered]);
		return;
	}
	if (verdict == .deny) {
		logReject(orig, host, "l7-deny");
		return;
	}

	// L7 allow SUPERSEDES the L4 CIDR deny-list for the re-resolved IP (still
	// gated by the non-overridable hard floor). A no_match host falls back to
	// the instance L4 policy. Either way the hard floor always applies.
	const supersede_l4 = verdict == .allow;
	const up_fd = dialUpstream(host, orig.port, supersede_l4) orelse {
		logReject(orig, host, "no-vetted-upstream");
		return;
	};
	defer _ = c.close(up_fd);

	if (!writeAll(up_fd, buf[0..buffered])) return;
	relay(client_fd, up_fd);
}

// --- terminate-tier handoff to the mitmproxy backend ---

fn terminateHandoff(client_fd: c_int, host: []const u8, orig: Orig, buffered: []const u8) void {
	// Pick the first re-resolved address that clears the SSRF floor + instance
	// CIDR policy. vet-then-pin: mitmproxy connects to exactly this IP.
	const vetted = firstVettedAddr(host, orig.port) orelse {
		logReject(orig, host, "no-vetted-upstream");
		return;
	};

	const mfd = connectLoopback(mitm_port) orelse {
		logReject(orig, host, "terminate-backend-down");
		return;
	};
	defer _ = c.close(mfd);
	setTimeouts(mfd);

	// SOCKS5 client to mitmproxy carrying the vetted IP as the CONNECT target.
	if (!socks5ClientHandshake(mfd, vetted, orig.port)) {
		logReject(orig, host, "terminate-socks-failed");
		return;
	}
	if (!writeAll(mfd, buffered)) return;
	relay(client_fd, mfd);
}

/// First resolved address for a terminate host, gated only by the
/// non-overridable hard floor. Terminate hosts always matched an explicit L7
/// `allow` (needsTerminate is true only for matched hosts), so the name allow
/// supersedes the L4 IP deny-list -- same composition as the passthrough
/// `dialUpstream(..., supersede_l4=true)` path. Does NOT connect (the backend does).
fn firstVettedAddr(host: []const u8, port: u16) ?filter.IpAddr {
	_ = port;
	var name_z: [256]u8 = undefined;
	if (host.len >= name_z.len) return null;
	@memcpy(name_z[0..host.len], host);
	name_z[host.len] = 0;

	var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
	hints.ai_family = c.AF_UNSPEC;
	hints.ai_socktype = c.SOCK_STREAM;

	var res: ?*c.struct_addrinfo = null;
	if (c.getaddrinfo(@ptrCast(&name_z), null, &hints, &res) != 0) return null;
	const list = res orelse return null;
	defer c.freeaddrinfo(list);

	var it: ?*c.struct_addrinfo = list;
	while (it) |ai| : (it = ai.ai_next) {
		const sa = ai.ai_addr orelse continue;
		const ip = sockaddrToIp(sa) orelse continue;
		if (filter.isHardBlocked(ip)) continue;
		return ip;
	}
	return null;
}

fn connectLoopback(port: u16) ?c_int {
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return null;
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = std.mem.nativeToBig(u32, 0x7f000001);
	if (c_connect(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) {
		_ = c.close(fd);
		return null;
	}
	return fd;
}

/// Minimal SOCKS5 CONNECT client (no-auth) used to reach the mitmproxy
/// backend, carrying the vetted upstream IP as the target.
fn socks5ClientHandshake(fd: c_int, ip: filter.IpAddr, port: u16) bool {
	if (!writeAll(fd, &.{ 0x05, 0x01, 0x00 })) return false;
	var sel: [2]u8 = undefined;
	if (!readExact(fd, &sel)) return false;
	if (sel[0] != 0x05 or sel[1] != 0x00) return false;

	var req: [22]u8 = undefined;
	req[0] = 0x05;
	req[1] = 0x01;
	req[2] = 0x00;
	var n: usize = 4;
	switch (ip) {
		.ipv4 => |b| {
			req[3] = 0x01;
			@memcpy(req[4..8], &b);
			n = 8;
		},
		.ipv6 => |b| {
			req[3] = 0x04;
			@memcpy(req[4..20], &b);
			n = 20;
		},
	}
	req[n] = @intCast((port >> 8) & 0xff);
	req[n + 1] = @intCast(port & 0xff);
	n += 2;
	if (!writeAll(fd, req[0..n])) return false;

	var head: [4]u8 = undefined;
	if (!readExact(fd, &head)) return false;
	if (head[0] != 0x05 or head[1] != 0x00) return false;
	const tail_len: usize = switch (head[3]) {
		0x01 => 4 + 2,
		0x04 => 16 + 2,
		0x03 => blk: {
			var lb: [1]u8 = undefined;
			if (!readExact(fd, &lb)) return false;
			break :blk @as(usize, lb[0]) + 2;
		},
		else => return false,
	};
	var tail: [256 + 2]u8 = undefined;
	if (tail_len > tail.len) return false;
	return readExact(fd, tail[0..tail_len]);
}

// --- SOCKS5 server side ---

fn socks5Accept(fd: c_int) ?Orig {
	var greet: [2]u8 = undefined;
	if (!readExact(fd, &greet)) return null;
	if (greet[0] != 0x05) return null;
	const nmethods = greet[1];
	if (nmethods > 0) {
		var methods: [255]u8 = undefined;
		if (!readExact(fd, methods[0..nmethods])) return null;
	}
	if (!writeAll(fd, &.{ 0x05, 0x00 })) return null; // select no-auth

	var rh: [4]u8 = undefined;
	if (!readExact(fd, &rh)) return null;
	if (rh[0] != 0x05 or rh[1] != 0x01) { // VER, CMD=CONNECT
		_ = writeAll(fd, &.{ 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }); // command not supported
		return null;
	}

	var orig: Orig = undefined;
	switch (rh[3]) { // ATYP
		0x01 => {
			var b: [4]u8 = undefined;
			if (!readExact(fd, &b)) return null;
			orig.addr = .{ .ipv4 = b };
		},
		0x04 => {
			var b: [16]u8 = undefined;
			if (!readExact(fd, &b)) return null;
			orig.addr = .{ .ipv6 = b };
		},
		else => {
			// Our shim never sends ATYP 0x03 (domain); refuse.
			_ = writeAll(fd, &.{ 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
			return null;
		},
	}
	var pb: [2]u8 = undefined;
	if (!readExact(fd, &pb)) return null;
	orig.port = (@as(u16, pb[0]) << 8) | pb[1];

	// Success: BND.ADDR 0.0.0.0:0. MUST precede the client's app bytes.
	if (!writeAll(fd, &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 })) return null;
	return orig;
}

// --- peek + classify ---

fn isHttpStart(b: u8) bool {
	return b >= 'A' and b <= 'Z';
}

fn peekClassify(
	fd: c_int,
	buf: []u8,
	buffered: *usize,
	out_host: []u8,
	out_path: []u8,
	out_sni: []u8,
) Classified {
	var n: usize = 0;
	while (true) {
		const got = c.recv(fd, @ptrCast(buf.ptr + n), buf.len - n, 0);
		if (got <= 0) {
			buffered.* = n;
			return .deny;
		}
		n += @intCast(got);
		buffered.* = n;

		if (buf[0] == 0x16) {
			switch (tls.extractSni(buf[0..n], out_sni)) {
				.sni => |s| return .{ .tls = s },
				.need_more => if (n >= buf.len) return .deny,
				.deny => return .deny,
			}
		} else if (isHttpStart(buf[0])) {
			switch (http.parseRequestHead(buf[0..n], out_host, out_path)) {
				.ok => |p| return .{ .http = p },
				.need_more => if (n >= buf.len) return .deny,
				.deny => return .deny,
			}
		} else {
			return .deny;
		}
	}
}

// --- upstream dial with SSRF + CIDR re-check ---

/// Dial the re-resolved upstream. `supersede_l4` is true when an explicit L7
/// `allow` matched the vhost -- then the only gate is the non-overridable hard
/// floor (the name allow overrides the L4 IP deny-list). When false (the vhost
/// matched no L7 rule), the resolved IP must also pass the instance L4 policy.
fn dialUpstream(host: []const u8, port: u16, supersede_l4: bool) ?c_int {
	var name_z: [256]u8 = undefined;
	if (host.len >= name_z.len) return null;
	@memcpy(name_z[0..host.len], host);
	name_z[host.len] = 0;

	var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
	hints.ai_family = c.AF_UNSPEC;
	hints.ai_socktype = c.SOCK_STREAM;

	var res: ?*c.struct_addrinfo = null;
	if (c.getaddrinfo(@ptrCast(&name_z), null, &hints, &res) != 0) return null;
	const list = res orelse return null;
	defer c.freeaddrinfo(list);

	var it: ?*c.struct_addrinfo = list;
	while (it) |ai| : (it = ai.ai_next) {
		const sa = ai.ai_addr orelse continue;
		const ip = sockaddrToIp(sa) orelse continue;

		// Non-overridable hard floor (loopback / this-net / link-local+metadata).
		// Applies even to an explicitly-allowed vhost.
		if (filter.isHardBlocked(ip)) {
			logLine("l7proxy: refusing {s}: resolves into a hard-blocked range (loopback/link-local/metadata)", .{host});
			continue;
		}
		// For an unlisted (no_match) vhost, defer to the instance L4 policy. An
		// explicit L7 allow skips this -- the name allow supersedes the IP deny.
		if (!supersede_l4) {
			lockRules();
			const denied = cidr_rs.evaluate(.tcp, ip, port) == .deny;
			unlockRules();
			if (denied) {
				logLine("l7proxy: refusing {s}: unlisted vhost, resolved IP denied by L4 policy", .{host});
				continue;
			}
		}

		// Vet-then-pin: connect to exactly the sockaddr we just vetted.
		if (connectVetted(ai, port)) |fd| return fd;
	}
	return null;
}

fn connectVetted(ai: *c.struct_addrinfo, port: u16) ?c_int {
	var storage: c.struct_sockaddr_storage = std.mem.zeroes(c.struct_sockaddr_storage);
	const alen = ai.ai_addrlen;
	if (alen == 0 or alen > @sizeOf(c.struct_sockaddr_storage)) return null;
	const dst: [*]u8 = @ptrCast(&storage);
	const src: [*]const u8 = @ptrCast(ai.ai_addr.?);
	@memcpy(dst[0..alen], src[0..alen]);

	if (ai.ai_family == c.AF_INET) {
		const sin: *c.struct_sockaddr_in = @ptrCast(@alignCast(&storage));
		sin.sin_port = std.mem.nativeToBig(u16, port);
	} else if (ai.ai_family == c.AF_INET6) {
		const sin6: *c.struct_sockaddr_in6 = @ptrCast(@alignCast(&storage));
		sin6.sin6_port = std.mem.nativeToBig(u16, port);
	} else return null;

	const fd = c.socket(ai.ai_family, c.SOCK_STREAM, 0);
	if (fd < 0) return null;
	setTimeouts(fd);
	if (c_connect(fd, @ptrCast(&storage), alen) != 0) {
		_ = c.close(fd);
		return null;
	}
	return fd;
}

fn sockaddrToIp(sa: *c.struct_sockaddr) ?filter.IpAddr {
	if (sa.sa_family == c.AF_INET) {
		const a4: *c.struct_sockaddr_in = @ptrCast(@alignCast(sa));
		return .{ .ipv4 = @bitCast(a4.sin_addr.s_addr) };
	} else if (sa.sa_family == c.AF_INET6) {
		const a6: *c.struct_sockaddr_in6 = @ptrCast(@alignCast(sa));
		return .{ .ipv6 = @as(*const [16]u8, @ptrCast(&a6.sin6_addr)).* };
	}
	return null;
}

// --- bidirectional splice ---

fn relay(a: c_int, b: c_int) void {
	var fds = [_]c.struct_pollfd{
		.{ .fd = a, .events = c.POLLIN, .revents = 0 },
		.{ .fd = b, .events = c.POLLIN, .revents = 0 },
	};
	var a_open = true;
	var b_open = true;
	var rbuf: [relay_buf]u8 = undefined;

	while (a_open or b_open) {
		fds[0].events = if (a_open) c.POLLIN else 0;
		fds[1].events = if (b_open) c.POLLIN else 0;
		const pr = c.poll(&fds, 2, relay_idle_ms);
		if (pr <= 0) return; // error or idle timeout -> tear down

		if (a_open and (fds[0].revents & (c.POLLIN | c.POLLHUP | c.POLLERR)) != 0) {
			const n = c.recv(a, &rbuf, rbuf.len, 0);
			if (n <= 0) {
				a_open = false;
				_ = c.shutdown(b, c.SHUT_WR);
			} else if (!writeAll(b, rbuf[0..@intCast(n)])) return;
		}
		if (b_open and (fds[1].revents & (c.POLLIN | c.POLLHUP | c.POLLERR)) != 0) {
			const n = c.recv(b, &rbuf, rbuf.len, 0);
			if (n <= 0) {
				b_open = false;
				_ = c.shutdown(a, c.SHUT_WR);
			} else if (!writeAll(a, rbuf[0..@intCast(n)])) return;
		}
	}
}

// --- small io helpers ---

const MSG_NOSIGNAL: c_int = c.MSG_NOSIGNAL;

fn writeAll(fd: c_int, buf: []const u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = c.send(fd, @ptrCast(buf.ptr + off), buf.len - off, MSG_NOSIGNAL);
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

fn readExact(fd: c_int, buf: []u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = c.recv(fd, @ptrCast(buf.ptr + off), buf.len - off, 0);
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

fn setTimeouts(fd: c_int) void {
	var tv: c.struct_timeval = .{ .tv_sec = io_timeout_secs, .tv_usec = 0 };
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval));
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(c.struct_timeval));
}

// --- logging (stderr; the launcher redirects it to cogbox.log) ---

fn logLine(comptime fmt: []const u8, args: anytype) void {
	std.debug.print(fmt ++ "\n", args);
}

fn logReject(orig: Orig, host: []const u8, reason: []const u8) void {
	var ipbuf: [46]u8 = undefined;
	const ips = formatIp(orig.addr, &ipbuf);
	std.debug.print("l7proxy: reject host={s} orig={s}:{d} reason={s}\n", .{ host, ips, orig.port, reason });
}

fn formatIp(addr: filter.IpAddr, buf: []u8) []const u8 {
	return switch (addr) {
		.ipv4 => |ip| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?",
		.ipv6 => "v6",
	};
}
