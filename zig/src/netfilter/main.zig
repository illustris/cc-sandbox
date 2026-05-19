const std = @import("std");
const filter = @import("filter");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("dlfcn.h");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("errno.h");
	@cInclude("stdlib.h");
	@cInclude("string.h");
});

// netdb / arpa constants and prototypes -- declared directly. @cInclude of
// netdb.h and arpa/inet.h drags in glibc's FORTIFY_SOURCE wrappers which
// translate badly through @cImport in ReleaseSafe builds.
const EAI_NONAME: c_int = -2;
const HOST_NOT_FOUND: c_int = 1;
const AF_INET_LOCAL: c_int = 2;
const AF_INET6_LOCAL: c_int = 10;

extern "c" fn __h_errno_location() *c_int;
extern "c" fn inet_pton(af: c_int, src: [*:0]const u8, dst: *anyopaque) c_int;

// POSIX I/O -- declared directly to avoid glibc macro issues with fcntl.h
const O_RDONLY: c_int = 0;
const SEEK_SET: c_int = 0;
extern "c" fn @"open"(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn lseek(fd: c_int, offset: c_long, whence: c_int) c_long;
extern "c" fn close(fd: c_int) c_int;

// RTLD_NEXT = ((void *)-1)
const RTLD_NEXT: *anyopaque = @ptrFromInt(~@as(usize, 0));

// --- State ---

var ruleset: filter.RuleSet = .{};
var initialized: bool = false;
var reload_pending = std.atomic.Value(bool).init(false);

// Rules file descriptor -- opened during lazy init (after passt's
// close_open_files but before seccomp), kept open for lseek+read reloads.
var rules_fd: c_int = -1;

// --- Real libc function pointers ---

const ConnectFn = *const fn (c_int, ?*const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int;
const SendtoFn = *const fn (c_int, ?*const anyopaque, usize, c_int, ?*const c.struct_sockaddr, c.socklen_t) callconv(.c) isize;
const SendmsgFn = *const fn (c_int, ?*const c.struct_msghdr, c_int) callconv(.c) isize;
const SendmmsgFn = *const fn (c_int, ?[*]c.struct_mmsghdr, c_uint, c_int) callconv(.c) c_int;

// Resolver entry points. The struct types are kept opaque -- we never
// dereference them in the shim, only forward to libc.
const GetaddrinfoFn = *const fn (?[*:0]const u8, ?[*:0]const u8, ?*const anyopaque, ?*?*anyopaque) callconv(.c) c_int;
const GethostbynameFn = *const fn (?[*:0]const u8) callconv(.c) ?*anyopaque;
const Gethostbyname2Fn = *const fn (?[*:0]const u8, c_int) callconv(.c) ?*anyopaque;
const GethostbynameRFn = *const fn (?[*:0]const u8, ?*anyopaque, [*]u8, usize, ?*?*anyopaque, ?*c_int) callconv(.c) c_int;
const Gethostbyname2RFn = *const fn (?[*:0]const u8, c_int, ?*anyopaque, [*]u8, usize, ?*?*anyopaque, ?*c_int) callconv(.c) c_int;

var real_connect: ?ConnectFn = null;
var real_sendto: ?SendtoFn = null;
var real_sendmsg: ?SendmsgFn = null;
var real_sendmmsg: ?SendmmsgFn = null;
var real_getaddrinfo: ?GetaddrinfoFn = null;
var real_gethostbyname: ?GethostbynameFn = null;
var real_gethostbyname2: ?Gethostbyname2Fn = null;
var real_gethostbyname_r: ?GethostbynameRFn = null;
var real_gethostbyname2_r: ?Gethostbyname2RFn = null;

fn resolve(comptime name: [*:0]const u8) *anyopaque {
	return c.dlsym(RTLD_NEXT, name) orelse @panic("netfilter: dlsym failed");
}

// --- Initialization ---
// Lazy init on first intercepted call. passt's startup sequence:
//   1. .init_array constructors run (before main)
//   2. main() → isolate_initial() → close_open_files() closes all fds > 2
//   3. main() setup: creates sockets, calls connect() for probing etc.
//   4. main() → isolate_postfork() → seccomp applied
//
// Our wrappers intercept connect() calls during step 3, which triggers
// init(). At this point close_open_files is done (so our fd won't be
// closed) and seccomp isn't applied yet (so open() works). This is the
// only safe window for initialization.

fn init() void {
	if (initialized) return;

	real_connect = @ptrCast(resolve("connect"));
	real_sendto = @ptrCast(resolve("sendto"));
	real_sendmsg = @ptrCast(resolve("sendmsg"));
	real_sendmmsg = @ptrCast(resolve("sendmmsg"));
	real_getaddrinfo = @ptrCast(resolve("getaddrinfo"));
	real_gethostbyname = @ptrCast(resolve("gethostbyname"));
	real_gethostbyname2 = @ptrCast(resolve("gethostbyname2"));
	real_gethostbyname_r = @ptrCast(resolve("gethostbyname_r"));
	real_gethostbyname2_r = @ptrCast(resolve("gethostbyname2_r"));

	// Install SIGUSR1 handler for rule reload.
	// Requires rt_sigreturn in passt's seccomp allowlist.
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = handleSigusr1;
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);

	// Open rules file and keep fd for seccomp-safe reloads.
	const env: ?[*:0]const u8 = c.getenv("NETFILTER_RULES");
	if (env) |ptr| {
		const fd = @"open"(ptr, O_RDONLY, 0);
		if (fd >= 0) {
			rules_fd = fd;
		}
	}

	loadRules();
	initialized = true;
}

/// Re-read rules from the pre-opened fd. Seccomp-safe: uses only lseek+read.
fn loadRules() void {
	if (rules_fd < 0) return;

	if (lseek(rules_fd, 0, SEEK_SET) < 0) return;

	var buf: [8192]u8 = undefined;
	var total: usize = 0;
	while (total < buf.len) {
		const n = read(rules_fd, @ptrCast(&buf[total]), buf.len - total);
		if (n <= 0) break;
		total += @intCast(n);
	}
	if (total == 0) return;
	ruleset = filter.parseRules(buf[0..total]);
}

fn handleSigusr1(_: std.posix.SIG) callconv(.c) void {
	reload_pending.store(true, .release);
}

fn checkReload() void {
	if (reload_pending.load(.acquire)) {
		reload_pending.store(false, .release);
		loadRules();
	}
}

// --- Address extraction ---

const AddrInfo = struct {
	addr: filter.IpAddr,
	port: u16,
};

fn extractAddr(sa: *const c.struct_sockaddr) ?AddrInfo {
	if (sa.sa_family == c.AF_INET) {
		const a4: *const c.struct_sockaddr_in = @ptrCast(@alignCast(sa));
		return .{
			.addr = .{ .ipv4 = @bitCast(a4.sin_addr.s_addr) },
			.port = std.mem.bigToNative(u16, a4.sin_port),
		};
	} else if (sa.sa_family == c.AF_INET6) {
		const a6: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(sa));
		return .{
			.addr = .{ .ipv6 = @as(*const [16]u8, @ptrCast(&a6.sin6_addr)).* },
			.port = std.mem.bigToNative(u16, a6.sin6_port),
		};
	}
	return null;
}

fn denyErrno() void {
	std.c._errno().* = c.ENETUNREACH;
}

// --- Exported wrappers ---

export fn connect(fd: c_int, addr: ?*const c.struct_sockaddr, len: c.socklen_t) callconv(.c) c_int {
	init();
	checkReload();

	if (addr) |a| {
		if (extractAddr(a)) |info| {
			if (ruleset.evaluate(info.addr, info.port) == .deny) {
				denyErrno();
				return -1;
			}
		}
	}
	return real_connect.?(fd, addr, len);
}

export fn sendto(fd: c_int, buf: ?*const anyopaque, len: usize, flags: c_int, dest_addr: ?*const c.struct_sockaddr, addrlen: c.socklen_t) callconv(.c) isize {
	init();
	checkReload();

	if (dest_addr) |a| {
		if (extractAddr(a)) |info| {
			if (ruleset.evaluate(info.addr, info.port) == .deny) {
				denyErrno();
				return -1;
			}
		}
	}
	return real_sendto.?(fd, buf, len, flags, dest_addr, addrlen);
}

export fn sendmsg(fd: c_int, msg: ?*const c.struct_msghdr, flags: c_int) callconv(.c) isize {
	init();
	checkReload();

	if (msg) |m| {
		if (m.msg_name) |name| {
			const sa: *const c.struct_sockaddr = @ptrCast(@alignCast(name));
			if (extractAddr(sa)) |info| {
				if (ruleset.evaluate(info.addr, info.port) == .deny) {
					denyErrno();
					return -1;
				}
			}
		}
	}
	return real_sendmsg.?(fd, msg, flags);
}

export fn sendmmsg(fd: c_int, msgvec: ?[*]c.struct_mmsghdr, vlen: c_uint, flags: c_int) callconv(.c) c_int {
	init();
	checkReload();

	if (msgvec) |vec| {
		if (vlen > 0) {
			if (vec[0].msg_hdr.msg_name) |name| {
				const sa: *const c.struct_sockaddr = @ptrCast(@alignCast(name));
				if (extractAddr(sa)) |info| {
					if (ruleset.evaluate(info.addr, info.port) == .deny) {
						denyErrno();
						return -1;
					}
				}
			}
		}
	}
	return real_sendmmsg.?(fd, msgvec, vlen, flags);
}

// --- DNS resolver wrappers ---
//
// Gate libc-level name resolution by consulting `ruleset.evaluateDns()`.
// On deny we never call libc, so no DNS packet is emitted upstream and the
// caller sees the standard "host not found" return.
//
// Numeric IP literals (e.g. `getaddrinfo("1.2.3.4", ...)`) bypass DNS
// rules -- they aren't names, and blocking them here would surprise
// callers that happen to use the resolver API for numeric lookups.

fn isNumericLiteralC(name: [*:0]const u8) bool {
	var buf4: [4]u8 = undefined;
	var buf6: [16]u8 = undefined;
	if (inet_pton(AF_INET_LOCAL, name, &buf4) == 1) return true;
	if (inet_pton(AF_INET6_LOCAL, name, &buf6) == 1) return true;
	return false;
}

fn dnsDenies(name_c: [*:0]const u8) bool {
	if (isNumericLiteralC(name_c)) return false;
	const slice = std.mem.span(name_c);
	return ruleset.evaluateDns(slice) == .deny;
}

fn setHostNotFound() void {
	__h_errno_location().* = HOST_NOT_FOUND;
}

export fn getaddrinfo(
	node: ?[*:0]const u8,
	service: ?[*:0]const u8,
	hints: ?*const anyopaque,
	res: ?*?*anyopaque,
) callconv(.c) c_int {
	init();
	checkReload();

	if (node) |n| {
		if (dnsDenies(n)) return EAI_NONAME;
	}
	return real_getaddrinfo.?(node, service, hints, res);
}

export fn gethostbyname(name: ?[*:0]const u8) callconv(.c) ?*anyopaque {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			setHostNotFound();
			return null;
		}
	}
	return real_gethostbyname.?(name);
}

export fn gethostbyname2(name: ?[*:0]const u8, af: c_int) callconv(.c) ?*anyopaque {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			setHostNotFound();
			return null;
		}
	}
	return real_gethostbyname2.?(name, af);
}

export fn gethostbyname_r(
	name: ?[*:0]const u8,
	ret: ?*anyopaque,
	buf: [*]u8,
	buflen: usize,
	result: ?*?*anyopaque,
	h_errnop: ?*c_int,
) callconv(.c) c_int {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			// glibc convention: return 0, set *result = NULL, set *h_errnop
			// = HOST_NOT_FOUND. Callers that read errno also expect 0.
			if (result) |r| r.* = null;
			if (h_errnop) |hep| hep.* = HOST_NOT_FOUND;
			return 0;
		}
	}
	return real_gethostbyname_r.?(name, ret, buf, buflen, result, h_errnop);
}

export fn gethostbyname2_r(
	name: ?[*:0]const u8,
	af: c_int,
	ret: ?*anyopaque,
	buf: [*]u8,
	buflen: usize,
	result: ?*?*anyopaque,
	h_errnop: ?*c_int,
) callconv(.c) c_int {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			if (result) |r| r.* = null;
			if (h_errnop) |hep| hep.* = HOST_NOT_FOUND;
			return 0;
		}
	}
	return real_gethostbyname2_r.?(name, af, ret, buf, buflen, result, h_errnop);
}
