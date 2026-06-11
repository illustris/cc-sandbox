// Regenerate the runtime rules file (read by the LD_PRELOAD filter) and
// signal a running passt to re-read it. Emits both the CIDR allow/deny
// section AND the remap section from the loaded .network object, so the
// `rules` and `remap` verbs can each rewrite the file independently
// without dropping the other layer.

const std = @import("std");
const rule = @import("rule.zig");
const filter = @import("filter");

/// True when L7 vhost filtering is active for this instance: `.network.l7`
/// is an object whose `rules` array has at least one entry. An empty L7 rule
/// set must NOT activate the funnel (it would blackhole all web egress).
pub fn l7Active(network: std.json.Value) bool {
	if (network != .object) return false;
	const l7 = network.object.getPtr("l7") orelse return false;
	if (l7.* != .object) return false;
	const rules = l7.object.getPtr("rules") orelse return false;
	if (rules.* != .array) return false;
	return rules.array.items.len > 0;
}

/// Render `.network` to wire-format rule lines for the LD_PRELOAD shim. Pure
/// -- no I/O. Ordering on disk: L7 fail-closed denies, user CIDR rules, user
/// remaps, then the auto-injected L7 funnel remaps.
///
/// When L7 is active we funnel all guest 80/443 to the host-side proxy and
/// force everything else on those ports to fail closed:
///   - all guest IPv6 TCP/UDP is denied (the funnel is IPv4-only in v1, so
///     v6 web egress would otherwise bypass the proxy entirely; DNS on port
///     53 stays implicitly allowed by the shim);
///   - guest UDP/443 + UDP/80 (QUIC / HTTP-3) is denied, forcing a downgrade
///     to inspectable TCP;
///   - guest TCP/443 + TCP/80 is remapped to the proxy (remap-implies-allow).
pub fn renderRules(allocator: std.mem.Allocator, network: std.json.Value, l7_base: u16, out: *std.ArrayList(u8)) !void {
	if (network != .object) return;
	const l7 = l7Active(network);

	if (l7) {
		// IPv6 fail-closed (all v6 TCP/UDP; DNS:53 still implicitly allowed)
		// + IPv4 QUIC fail-closed on the funneled ports. These go FIRST so
		// they win first-match over any broad user allow.
		try out.appendSlice(allocator,
			\\deny tcp ::/0
			\\deny udp ::/0
			\\deny udp 0.0.0.0/0:443
			\\deny udp 0.0.0.0/0:80
			\\
		);
	}

	if (network.object.getPtr("rules")) |rules_val| {
		if (rules_val.* == .array) {
			for (rules_val.array.items) |r| {
				if (r != .object) continue;
				const p = rule.ruleAction(r.object) orelse continue;
				const action_str = switch (p.action) {
					.allow => "allow",
					.deny => "deny",
				};
				try out.appendSlice(allocator, action_str);
				try out.append(allocator, ' ');
				try out.appendSlice(allocator, p.cidr);
				try out.append(allocator, '\n');
			}
		}
	}

	if (network.object.getPtr("remap")) |remap_val| {
		if (remap_val.* == .array) {
			for (remap_val.array.items) |r| {
				if (r != .object) continue;
				const from_v = r.object.getPtr("from") orelse continue;
				const to_v = r.object.getPtr("to") orelse continue;
				if (from_v.* != .string or to_v.* != .string) continue;
				try out.appendSlice(allocator, "remap ");
				try out.appendSlice(allocator, from_v.string);
				try out.appendSlice(allocator, " -> ");
				try out.appendSlice(allocator, to_v.string);
				try out.append(allocator, '\n');
			}
		}
	}

	if (l7) {
		// Funnel remaps LAST so a power user's explicit per-host remap above
		// wins by first-match and can deliberately route around the proxy.
		// Targets are this instance's per-instance loopback ports so multiple
		// L7 instances coexist without funnelling into each other's proxy.
		const ports = filter.l7PortsForBase(l7_base);
		var buf: [96]u8 = undefined;
		const tls_line = try std.fmt.bufPrint(&buf, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:{d}\n", .{ports.tls});
		try out.appendSlice(allocator, tls_line);
		const http_line = try std.fmt.bufPrint(&buf, "remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:{d}\n", .{ports.http});
		try out.appendSlice(allocator, http_line);
	}
}

/// Render `.network.l7` to the proxy's `l7-rules` wire format. Pure -- no I/O.
///   mode passthrough|terminate
///   allow|deny  <host>  [<path>]  [terminate|passthrough]  [insecure]
pub fn renderL7(allocator: std.mem.Allocator, network: std.json.Value, out: *std.ArrayList(u8)) !void {
	if (network != .object) return;
	const l7 = network.object.getPtr("l7") orelse return;
	if (l7.* != .object) return;

	// Terminate is the default tier; only an explicit `mode: passthrough`
	// opts the whole instance out.
	var mode_terminate = true;
	if (l7.object.getPtr("mode")) |m| {
		if (m.* == .string and std.mem.eql(u8, m.string, "passthrough")) mode_terminate = false;
	}
	try out.appendSlice(allocator, if (mode_terminate) "mode terminate\n" else "mode passthrough\n");

	const rules = l7.object.getPtr("rules") orelse return;
	if (rules.* != .array) return;
	for (rules.array.items) |r| {
		if (r != .object) continue;
		var action: []const u8 = undefined;
		var host: []const u8 = undefined;
		if (r.object.getPtr("allow")) |v| {
			if (v.* != .string) continue;
			action = "allow";
			host = v.string;
		} else if (r.object.getPtr("deny")) |v| {
			if (v.* != .string) continue;
			action = "deny";
			host = v.string;
		} else continue;

		try out.appendSlice(allocator, action);
		try out.append(allocator, ' ');
		try out.appendSlice(allocator, host);
		if (r.object.getPtr("path")) |p| {
			if (p.* == .string and p.string.len > 0) {
				try out.append(allocator, ' ');
				try out.appendSlice(allocator, p.string);
			}
		}
		if (r.object.getPtr("terminate")) |tv| {
			if (tv.* == .bool and tv.bool) try out.appendSlice(allocator, " terminate");
		}
		if (r.object.getPtr("passthrough")) |pv| {
			if (pv.* == .bool and pv.bool) try out.appendSlice(allocator, " passthrough");
		}
		if (r.object.getPtr("insecure_upstream")) |iv| {
			if (iv.* == .bool and iv.bool) try out.appendSlice(allocator, " insecure");
		}
		try out.append(allocator, '\n');
	}
}

pub fn writeRuntimeRules(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, network: std.json.Value, l7_base: u16) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try renderRules(allocator, network, l7_base, &out);
	try writeRuntimeFile(allocator, io, runtime_dir, "netfilter-rules", out.items);
}

/// Write `<runtime>/l7-rules` (the host-side proxy's rule file).
pub fn writeL7Rules(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, network: std.json.Value) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try renderL7(allocator, network, &out);
	try writeRuntimeFile(allocator, io, runtime_dir, "l7-rules", out.items);
}

fn writeRuntimeFile(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, name: []const u8, bytes: []const u8) !void {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, name });
	defer allocator.free(path);

	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var write_buf: [4096]u8 = undefined;
	var writer = f.writer(io, &write_buf);
	try writer.interface.writeAll(bytes);
	try writer.flush();
}

/// If <runtime>/passt.pid exists and the process is alive, send SIGUSR1.
/// Returns true if a signal was sent.
pub fn maybeSignalPasst(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8) !bool {
	return signalPidfile(allocator, io, runtime_dir, "passt.pid", std.posix.SIG.USR1);
}

/// If <runtime>/l7proxy.pid exists and the process is alive, send SIGHUP so
/// the L7 proxy re-reads netfilter-rules + l7-rules. No-op if not running.
pub fn maybeSignalL7proxy(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8) !bool {
	return signalPidfile(allocator, io, runtime_dir, "l7proxy.pid", std.posix.SIG.HUP);
}

fn signalPidfile(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, pidfile: []const u8, sig: std.posix.SIG) !bool {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, pidfile });
	defer allocator.free(path);

	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, path, .{}) catch |err| switch (err) {
		error.FileNotFound => return false,
		else => return err,
	};
	defer file.close(io);

	var read_buf: [64]u8 = undefined;
	var reader = file.reader(io, &read_buf);
	const contents = reader.interface.allocRemaining(allocator, .limited(64)) catch return false;
	defer allocator.free(contents);

	const trimmed = std.mem.trim(u8, contents, " \t\r\n");
	const pid = std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return false;

	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	std.posix.kill(pid, sig) catch return false;
	return true;
}

test "renderL7 wire format incl. insecure token" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[
		\\  {"allow":"plain.test"},
		\\  {"allow":"api.test","path":"/v1/"},
		\\  {"allow":"internal.svc","terminate":true,"insecure_upstream":true},
		\\  {"allow":"lab.svc","path":"/api/","insecure_upstream":true}
		\\]}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	const s = out.items;

	const has = struct {
		fn f(hay: []const u8, needle: []const u8) bool {
			return std.mem.indexOf(u8, hay, needle) != null;
		}
	}.f;
	try std.testing.expect(has(s, "mode terminate\n"));
	// insecure (no path) -> emitted after the terminate marker
	try std.testing.expect(has(s, "allow internal.svc terminate insecure\n"));
	// insecure + path -> path carries terminate, insecure trails
	try std.testing.expect(has(s, "allow lab.svc /api/ insecure\n"));
	// plain / path-only rules carry no insecure token
	try std.testing.expect(has(s, "allow plain.test\n"));
	try std.testing.expect(has(s, "allow api.test /v1/\n"));
	try std.testing.expect(!has(s, "plain.test insecure"));
}

test "renderRules funnel targets the per-instance base ports" {
	const gpa = std.testing.allocator;
	const src = "{\"l7\":{\"mode\":\"passthrough\",\"rules\":[{\"allow\":\"x.test\"}]}}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	// A named instance's base (default keeps 18443); funnel must target it.
	try renderRules(gpa, parsed.value, 18446, &out);
	const s = out.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18446\n") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:18447\n") != null);
	// this instance's render never mentions the default base
	try std.testing.expect(std.mem.indexOf(u8, s, "18443") == null);
}
