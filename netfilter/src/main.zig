const std = @import("std");
const filter = @import("filter.zig");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("dlfcn.h");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("errno.h");
	@cInclude("stdlib.h");
	@cInclude("string.h");
});

// POSIX file I/O -- declared directly to avoid glibc fcntl.h macro issues
const O_RDONLY: c_int = 0;
extern "c" fn @"open"(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn close(fd: c_int) c_int;

// RTLD_NEXT = ((void *)-1)
const RTLD_NEXT: *anyopaque = @ptrFromInt(~@as(usize, 0));

// --- State ---

var ruleset: filter.RuleSet = .{};
var initialized: bool = false;
var reload_pending = std.atomic.Value(bool).init(false);

// Rules file path (null-terminated in buffer for C open())
var rules_path_buf: [4097]u8 = undefined;
var rules_path_len: usize = 0;

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

fn init() void {
	if (initialized) return;

	real_connect = @ptrCast(resolve("connect"));
	real_sendto = @ptrCast(resolve("sendto"));
	real_sendmsg = @ptrCast(resolve("sendmsg"));
	real_sendmmsg = @ptrCast(resolve("sendmmsg"));

	// Install SIGUSR1 handler for live rule reload
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = handleSigusr1;
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);

	// Copy rules file path from environment (using libc getenv)
	const env: ?[*:0]const u8 = c.getenv("NETFILTER_RULES");
	if (env) |ptr| {
		const len = c.strlen(ptr);
		if (len > 0 and len < rules_path_buf.len) {
			@memcpy(rules_path_buf[0..len], ptr[0..len]);
			rules_path_buf[len] = 0;
			rules_path_len = len;
		}
	}

	loadRules();
	initialized = true;
}

fn loadRules() void {
	if (rules_path_len == 0) return;

	const path_z: [*:0]const u8 = @ptrCast(rules_path_buf[0..rules_path_len :0]);
	const fd = @"open"(path_z, O_RDONLY, 0);
	if (fd < 0) return;
	defer _ = close(fd);

	var buf: [8192]u8 = undefined;
	var total: usize = 0;
	while (total < buf.len) {
		const n = read(fd, @ptrCast(&buf[total]), buf.len - total);
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
