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

var real_connect: ?ConnectFn = null;
var real_sendto: ?SendtoFn = null;
var real_sendmsg: ?SendmsgFn = null;
var real_sendmmsg: ?SendmmsgFn = null;

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
