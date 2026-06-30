// Regenerate the runtime rules file (read by the LD_PRELOAD filter) and
// signal a running passt to re-read it. Emits both the CIDR allow/deny
// section AND the remap section from the loaded .network object, so the
// `rules` and `remap` verbs can each rewrite the file independently
// without dropping the other layer.

const std = @import("std");
const rule = @import("rule.zig");
const config = @import("config.zig");
const filter = @import("filter");
const secret_mod = @import("secret_module");
const secret_store = secret_mod.store;

/// True when L7 vhost filtering is active for this instance: `.network.l7` is
/// an object with a non-empty `rules` array OR a non-empty
/// `inject.specs` array. An inject spec implies a terminate-allow for its host
/// (see renderL7), so an inject-only plugin still funnels web egress. An empty
/// L7 config must NOT activate the funnel (it would blackhole all web egress).
pub fn l7Active(network: std.json.Value) bool {
	if (network != .object) return false;
	const l7 = network.object.getPtr("l7") orelse return false;
	if (l7.* != .object) return false;
	if (l7.object.getPtr("rules")) |rules| {
		if (rules.* == .array and rules.array.items.len > 0) return true;
	}
	if (injectSpecs(network)) |specs| {
		if (specs.items.len > 0) return true;
	}
	return false;
}

/// `.network.l7.inject.specs` array (by value; shares the items pointer), or
/// null when absent / not an array / inject is the legacy bool form / the
/// master `enabled` toggle is explicitly false. Gating here means all three
/// consumers (l7Active, renderL7's terminate-allow union, renderL7Inject)
/// honor `enabled:false` consistently -- no funnel, no terminate, no inject.
fn injectSpecs(network: std.json.Value) ?std.json.Array {
	if (network != .object) return null;
	const l7 = network.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const inj = l7.object.getPtr("inject") orelse return null;
	if (inj.* != .object) return null; // legacy bool form carries no plugin specs
	if (inj.object.getPtr("enabled")) |en| {
		if (en.* == .bool and !en.bool) return null;
	}
	const specs = inj.object.getPtr("specs") orelse return null;
	if (specs.* != .array) return null;
	return specs.array;
}

fn strField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
	const v = obj.get(key) orelse return null;
	if (v != .string) return null;
	return v.string;
}

/// An inject spec's optional non-standard service port (the port the guest
/// actually connects to). Accepts a JSON integer (a Nix manifest yields one)
/// or a numeric string (a hand-rolled conf may use one). Out-of-range / zero /
/// unparseable -> null: the spec simply isn't funnelled on a custom port and
/// falls back to the standard-port (80/443) assumption -- fail closed, never a
/// bogus remap. The funnel reads the port from HERE (renderRules is secret-free
/// and runs in the netfilter-rules path) rather than from the secret's audience.
fn injectPort(obj: std.json.ObjectMap) ?u16 {
	const v = obj.get("port") orelse return null;
	switch (v) {
		.integer => |n| {
			if (n < 1 or n > 65535) return null;
			return @intCast(n);
		},
		.string => |s| {
			const n = std.fmt.parseInt(u16, s, 10) catch return null;
			return if (n == 0) null else n;
		},
		else => return null,
	}
}

fn hostNamedInRules(rules: ?std.json.Array, host: []const u8) bool {
	const r = rules orelse return false;
	for (r.items) |item| {
		if (item != .object) continue;
		if (strField(item.object, "allow")) |h| {
			if (std.mem.eql(u8, h, host)) return true;
		}
		if (strField(item.object, "deny")) |h| {
			if (std.mem.eql(u8, h, host)) return true;
		}
	}
	return false;
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

		// Plus a funnel remap for every DISTINCT non-standard port an inject host
		// is served on. A host reached on e.g. :9200 (Elasticsearch) is otherwise
		// invisible to the proxy -- the guest's connect clears only the L4 CIDR
		// layer and egresses untouched, so its credential is never stamped (a 401
		// at the upstream). 80/443 are already funnelled above. We route the extra
		// port to the SAME http entry: peekClassify sniffs TLS vs plain HTTP by the
		// first byte, so one entry serves both, and the proxy preserves the real
		// dest port (carried over SOCKS5) when it dials upstream. NB this funnels
		// ALL guest TCP on that port through the proxy (as :80/:443 already are), so
		// the port must speak HTTP/TLS; a non-inject host on it is L7-evaluated and
		// spliced, never injected (the needs_inject gate stays host-scoped).
		if (injectSpecs(network)) |specs| {
			var seen: [32]u16 = undefined;
			var nseen: usize = 0;
			for (specs.items) |spec| {
				if (spec != .object) continue;
				const p = injectPort(spec.object) orelse continue;
				if (p == 80 or p == 443) continue; // already funnelled
				var dup = false;
				for (seen[0..nseen]) |q| {
					if (q == p) {
						dup = true;
						break;
					}
				}
				if (dup) continue;
				if (nseen < seen.len) {
					seen[nseen] = p;
					nseen += 1;
				}
				const inj_line = try std.fmt.bufPrint(&buf, "remap tcp 0.0.0.0/0:{d} -> tcp 127.0.0.1:{d}\n", .{ p, ports.http });
				try out.appendSlice(allocator, inj_line);
			}
		}
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

	const rules: ?std.json.Array = blk: {
		const r = l7.object.getPtr("rules") orelse break :blk null;
		if (r.* != .array) break :blk null;
		break :blk r.array;
	};
	if (rules) |rs| {
		for (rs.items) |r| {
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

	// Union inject-spec hosts into the terminate-allow set: a host that gets a
	// credential injected MUST be MITM-terminated (a header/cookie can't be
	// added on a spliced TLS flow), and it need not be separately allow-listed.
	// Emit `allow <host> terminate` for each inject host not already named by an
	// l7 rule. Whether injection actually fires for that host is decided
	// separately by renderL7Inject (only when the secret is bound + audience
	// matches); an unbound host still terminates and simply isn't injected.
	if (injectSpecs(network)) |specs| {
		for (specs.items) |spec| {
			if (spec != .object) continue;
			const h = strField(spec.object, "host") orelse continue;
			if (hostNamedInRules(rules, h)) continue;
			try out.appendSlice(allocator, "allow ");
			try out.appendSlice(allocator, h);
			try out.appendSlice(allocator, " terminate\n");
		}
	}
}

/// Render the host-side credential-injection conf (the
/// `COGBOX_L7_INJECT_CONF` the mitmproxy addon reads as a JSON list). For each
/// `.network.l7.inject.specs[]` entry, resolve its NAMED secret host-side
/// (instance store first, then global) and emit a conf element ONLY when the
/// secret is bound AND its audience matches the spec host. Unbound or
/// audience-mismatched specs render nothing -- fail closed: the addon then has
/// no spec for that host and never stamps a stale/foreign credential. The
/// cred_file is the store's value path; cred_format "raw" (the addon's
/// token_for reads its first non-empty line). NOT pure -- reads the store.
///
/// A bound secret whose meta.kind == anthropic-oauth (the per-user Claude
/// `setup-token` bind) FORCES style
/// "anthropic-oauth" + the shared host stub_token sentinel, overriding whatever
/// the spec declared: the addon's anthropic-oauth branch then stamps the real
/// Bearer ONLY over that placeholder. No `refresh` block is ever emitted here --
/// a setup-token is long-lived and bound once (S4.4). Every other kind keeps its
/// existing spec-driven style + optional spec `stub` rendering unchanged.
pub fn renderL7Inject(
	allocator: std.mem.Allocator,
	io: std.Io,
	network: std.json.Value,
	global_secrets_dir: []const u8,
	instance_secrets_dir: []const u8,
	out: *std.ArrayList(u8),
	hosts_out: *std.ArrayList(u8),
) !void {
	var arena_inst = std.heap.ArenaAllocator.init(allocator);
	defer arena_inst.deinit();
	const arena = arena_inst.allocator();

	var arr = std.json.Array.init(arena);
	if (injectSpecs(network)) |specs| {
		for (specs.items) |spec| {
			if (spec != .object) continue;
			const host = strField(spec.object, "host") orelse continue;
			const secret_name = strField(spec.object, "secret") orelse continue;
			var style = strField(spec.object, "style") orelse "bearer";

			const resolved = (try resolveSecret(arena, io, instance_secrets_dir, global_secrets_dir, secret_name)) orelse continue;
			if (!resolved.bound) continue;
			const audience = resolved.meta.audience orelse continue; // unset -> not injectable
			if (!std.mem.eql(u8, audience, host)) continue; // exfiltration gate

			// A kind=anthropic-oauth secret (the per-user Claude setup-token bind)
			// forces the anthropic-oauth inject style + the shared host stub
			// sentinel, overriding the spec's style/stub. The audience pin above
			// already proved this secret is bound for THIS host.
			const oauth_kind = std.mem.eql(u8, resolved.meta.kind, secret_mod.anthropic_oauth_kind);
			if (oauth_kind) style = secret_mod.anthropic_oauth_kind;

			var el: std.json.ObjectMap = .empty;
			try el.put(arena, "host", .{ .string = host });
			try el.put(arena, "style", .{ .string = style });
			try el.put(arena, "cred_file", .{ .string = resolved.value_path });
			try el.put(arena, "cred_format", .{ .string = "raw" });
			if (strField(spec.object, "cookieName")) |cn| {
				try el.put(arena, "cookie_name", .{ .string = cn });
			}
			if (oauth_kind) {
				// A setup-token is long-lived/static -> NO refresh block, just the
				// stub the host redacted into the guest's cred file.
				try el.put(arena, "stub_token", .{ .string = secret_mod.claude_stub_token });
			} else if (strField(spec.object, "stub")) |st| {
				try el.put(arena, "stub_token", .{ .string = st });
			}
			try arr.append(.{ .object = el });

			// Mirror the host into the proxy's inject-host list (one per line):
			// it routes this host's PLAIN-HTTP egress through the terminate
			// backend too, so an `http://` vhost's credential is still stamped.
			// Only EMITTED (bound + audience-matched) hosts go here, so an
			// unbound/mismatched spec neither injects nor reroutes HTTP.
			try hosts_out.appendSlice(allocator, host);
			try hosts_out.append(allocator, '\n');
		}
	}
	try config.writeJqTab(allocator, out, .{ .array = arr });
}

/// Whether THIS render should seed the harness Claude inject spec: true ONLY in
/// the container-enforcer context. cogworx sets BOTH enforcer-private secret-store
/// overrides (COGBOX_GLOBAL_SECRETS_DIR / COGBOX_INSTANCE_SECRETS_DIR) exclusively
/// on the enforcer (and the stopped-instance worker) pods -- never on the VM boot
/// render or the non-enforcing single-pod agent -- so their presence is the
/// "enforcement on + container target" signal with no extra wiring. Pure, so the
/// gate is unit-testable. (Both must be set: an enforcer always sets both together.)
pub fn seedClaudeInject(global_override: ?[]const u8, instance_override: ?[]const u8) bool {
	return global_override != null and instance_override != null;
}

/// Whether the reserved per-user `claude-oauth` secret is actually BOUND in this
/// instance's store (instance store shadowing global -- the same precedence
/// renderL7Inject uses). The container seed (seedClaudeInjectSpec) is additionally
/// gated on this so renderL7 / renderRules terminate-allow + funnel
/// api.anthropic.com ONLY for a connected owner's sandbox.
///
/// 5a review gap #1: seeding on every enforce-ON container render made renderL7
/// terminate-allow api.anthropic.com on EVERY container sandbox (superseding the L4
/// deny-list) even for never-connected / non-claude owners. Binding claude-oauth
/// already triggers a re-render (secret-add hot-reload + the enforcer reconcile), so
/// gating the seed on `bound` has no race -- a connect re-renders with the secret
/// present, a disconnect re-renders with it gone. Reads the store, so NOT pure.
pub fn claudeOAuthBound(
	arena: std.mem.Allocator,
	io: std.Io,
	instance_secrets_dir: []const u8,
	global_secrets_dir: []const u8,
) !bool {
	const resolved = (try resolveSecret(arena, io, instance_secrets_dir, global_secrets_dir, secret_mod.claude_oauth_secret)) orelse return false;
	return resolved.bound;
}

/// Seed the harness-owned Claude inject spec into `network.l7.inject.specs[]` so a
/// bound per-user `claude-oauth` setup-token actually renders. The step-3 reconcile BINDS the `claude-oauth` secret (kind=anthropic-oauth,
/// audience=api.anthropic.com), but renderL7Inject only iterates specs the config
/// declares -- with nothing naming that secret the bind is INERT. This is the
/// load-bearing link the step-4 review flagged.
///
/// Called only in the container-enforcer render (see seedClaudeInject). The spec is
/// HARMLESS when the secret is unbound: renderL7Inject emits an element ONLY when the
/// named secret is bound AND its audience == host, so a sandbox whose owner never
/// connected Claude (or a non-claude harness) renders nothing for it. It is also
/// additive -- a plugin/seed spec already targeting the host is left untouched
/// (idempotent), so re-renders and plugin-contributed specs are undisturbed.
///
/// Creates `.l7` / `.l7.inject` / `.l7.inject.specs` on demand and folds a legacy
/// bool `inject` (which carries no specs) into the object form. Mutates `network`
/// in place; new values are allocated in `arena` (the config tree's arena).
pub fn seedClaudeInjectSpec(arena: std.mem.Allocator, network: *std.json.Value) !void {
	if (network.* != .object) return; // "full"/"none" mode carries no L7 object

	// .network.l7 (object), created on demand.
	const l7 = blk: {
		if (network.object.getPtr("l7")) |v| {
			if (v.* == .object) break :blk v;
		}
		try network.object.put(arena, "l7", .{ .object = .empty });
		break :blk network.object.getPtr("l7").?;
	};

	// .network.l7.inject (object). A legacy bool `inject: true`/`false` carries no
	// specs, so replace it with the object form the seed can land in.
	const inj = blk: {
		if (l7.object.getPtr("inject")) |v| {
			if (v.* == .object) break :blk v;
		}
		try l7.object.put(arena, "inject", .{ .object = .empty });
		break :blk l7.object.getPtr("inject").?;
	};

	// .network.l7.inject.specs (array), created on demand.
	const specs = blk: {
		if (inj.object.getPtr("specs")) |v| {
			if (v.* == .array) break :blk &v.array;
		}
		try inj.object.put(arena, "specs", .{ .array = std.json.Array.init(arena) });
		break :blk &inj.object.getPtr("specs").?.array;
	};

	// Idempotent BUT shadow-safe (5a review gap #2): skip ONLY when a spec already
	// names OUR reserved claude-oauth secret for this host (a prior seed / re-render
	// -- never add a duplicate). A pre-existing spec that targets api.anthropic.com
	// under a DIFFERENT secret name (e.g. a plugin's) must NOT suppress the per-user
	// bind: appending ours anyway guarantees the connected owner's claude-oauth still
	// renders, instead of being silently shadowed by the plugin spec.
	for (specs.items) |s| {
		if (s != .object) continue;
		const h = strField(s.object, "host") orelse continue;
		if (!std.ascii.eqlIgnoreCase(h, secret_mod.anthropic_api_host)) continue;
		const sn = strField(s.object, "secret") orelse continue;
		if (std.mem.eql(u8, sn, secret_mod.claude_oauth_secret)) return; // our seed already present
	}

	// {host, style, secret}: the secret's kind=anthropic-oauth drives the actual
	// style/stub override in renderL7Inject, but declare style explicitly so the
	// config reads truthfully. No value/path/stub here -- a spec only NAMES a
	// credential (the same constraint plugin inject specs carry).
	var spec: std.json.ObjectMap = .empty;
	try spec.put(arena, "host", .{ .string = secret_mod.anthropic_api_host });
	try spec.put(arena, "style", .{ .string = secret_mod.anthropic_oauth_kind });
	try spec.put(arena, "secret", .{ .string = secret_mod.claude_oauth_secret });
	try specs.append(.{ .object = spec });
}

/// Resolve a named secret: an instance-produced secret (e.g. a sidecar-minted
/// session) shadows a global operator-bound one of the same name.
fn resolveSecret(
	arena: std.mem.Allocator,
	io: std.Io,
	instance_dir: []const u8,
	global_dir: []const u8,
	name: []const u8,
) !?secret_store.Resolved {
	if (try secret_store.lookup(arena, io, instance_dir, name)) |r| {
		if (r.bound) return r;
	}
	return try secret_store.lookup(arena, io, global_dir, name);
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

/// Write `<runtime>/l7-inject-conf.json` (the mitmproxy addon's
/// COGBOX_L7_INJECT_CONF) AND `<runtime>/l7-inject-hosts` (the L7 proxy's
/// plain-HTTP inject-routing list). Resolves each spec's named secret against
/// the per-instance then global store. Both files are written from the same
/// pass so the proxy's HTTP routing can never drift from what the addon injects.
pub fn writeL7Inject(
	allocator: std.mem.Allocator,
	io: std.Io,
	runtime_dir: []const u8,
	network: std.json.Value,
	global_secrets_dir: []const u8,
	instance_secrets_dir: []const u8,
) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(allocator);
	try renderL7Inject(allocator, io, network, global_secrets_dir, instance_secrets_dir, &out, &hosts);
	try writeRuntimeFile(allocator, io, runtime_dir, "l7-inject-conf.json", out.items);
	try writeRuntimeFile(allocator, io, runtime_dir, "l7-inject-hosts", hosts.items);
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

test "l7Active counts inject specs (inject-only instance still funnels)" {
	const gpa = std.testing.allocator;
	{
		const src = "{\"l7\":{\"rules\":[],\"inject\":{\"enabled\":true,\"specs\":[{\"host\":\"a.test\",\"secret\":\"s\"}]}}}";
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		try std.testing.expect(l7Active(parsed.value));
	}
	{
		const src = "{\"l7\":{\"rules\":[],\"inject\":{\"enabled\":true,\"specs\":[]}}}";
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		try std.testing.expect(!l7Active(parsed.value));
	}
}

test "injectSpecs honors the enabled:false master toggle" {
	const gpa = std.testing.allocator;
	const src = "{\"l7\":{\"rules\":[],\"inject\":{\"enabled\":false,\"specs\":[{\"host\":\"a.test\",\"secret\":\"s\"}]}}}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	try std.testing.expect(!l7Active(parsed.value)); // disabled -> no funnel
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out); // and no terminate-allow union
	try std.testing.expect(std.mem.indexOf(u8, out.items, "a.test") == null);
}

test "renderL7 unions inject hosts as terminate-allows, deduped against existing rules" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[{"allow":"already.test","terminate":true}],
		\\ "inject":{"enabled":true,"specs":[
		\\   {"host":"api.example.com","style":"bearer","secret":"s1"},
		\\   {"host":"already.test","style":"bearer","secret":"s2"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	const s = out.items;
	// an inject host not already named gets a terminate allow appended
	try std.testing.expect(std.mem.indexOf(u8, s, "allow api.example.com terminate\n") != null);
	// a host already named by an l7 rule is NOT duplicated by the union
	try std.testing.expect(std.mem.count(u8, s, "already.test") == 1);
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

test "renderRules funnels non-standard inject-host ports (deduped, 80/443 excluded)" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[],"inject":{"enabled":true,"specs":[
		\\  {"host":"es.internal","style":"basic","secret":"es","port":9200},
		\\  {"host":"es2.internal","style":"basic","secret":"es2","port":9200},
		\\  {"host":"kibana.internal","style":"basic","secret":"kb","port":"5601"},
		\\  {"host":"std-https.internal","style":"bearer","secret":"h","port":443},
		\\  {"host":"std-http.internal","style":"bearer","secret":"p","port":80},
		\\  {"host":"no-port.internal","style":"bearer","secret":"n"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	const s = out.items;

	// :9200 funnels to the http entry (base+1); declared twice but emitted once.
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:9200 -> tcp 127.0.0.1:18444\n") != null);
	try std.testing.expect(std.mem.count(u8, s, "0.0.0.0/0:9200 ->") == 1);
	// a numeric-string port is honored too.
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:5601 -> tcp 127.0.0.1:18444\n") != null);
	// 80/443 are already the standard funnel -- no duplicate custom remap for them.
	try std.testing.expect(std.mem.count(u8, s, "0.0.0.0/0:443 ->") == 1);
	try std.testing.expect(std.mem.count(u8, s, "0.0.0.0/0:80 ->") == 1);
}

// A self-made instance store dir (relative to cwd) for the renderL7Inject IO
// tests; the caller owns teardown. Returns the dir name allocated in `gpa`.
fn tmpStoreDir(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-inject-test-{s}", .{hexb});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

test "renderL7Inject: kind=anthropic-oauth forces style + the shared stub sentinel, no refresh" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	// Bind the reserved claude-oauth secret: kind=anthropic-oauth, audience pinned
	// to the spec host. The VALUE is a fictional (OSS-clean) setup-token.
	try secret_store.add(gpa, io, inst_dir, "claude-oauth", "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = "api.anthropic.com",
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// The spec deliberately declares a DIFFERENT style + stub: the secret's kind
	// must override both.
	const src =
		\\{"l7":{"mode":"terminate","inject":{"enabled":true,"specs":[
		\\  {"host":"api.anthropic.com","style":"bearer","secret":"claude-oauth","stub":"ignored-spec-stub"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(gpa);
	// No global store needed (the instance store binds the secret).
	try renderL7Inject(gpa, io, parsed.value, "zig-inject-test-no-global", inst_dir, &out, &hosts);
	const s = out.items;

	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"anthropic-oauth\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"cred_format\": \"raw\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, secret_mod.claude_stub_token) != null);
	// the spec's declared bearer style + stub did NOT win
	try std.testing.expect(std.mem.indexOf(u8, s, "ignored-spec-stub") == null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"bearer\"") == null);
	// a setup-token is static -> no refresh block is ever emitted here
	try std.testing.expect(std.mem.indexOf(u8, s, "refresh") == null);
	// the host is mirrored into the plain-HTTP inject-routing list
	try std.testing.expect(std.mem.indexOf(u8, hosts.items, "api.anthropic.com") != null);
}

test "renderL7Inject: a bearer-kind secret keeps the spec's style + spec stub (other kinds unchanged)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	try secret_store.add(gpa, io, inst_dir, "api-token", "tok-abc123", .{
		.audience = "api.example.com",
		.kind = "bearer",
		.tier = "durable",
		.bound_at = 1,
	});

	const src =
		\\{"l7":{"mode":"terminate","inject":{"enabled":true,"specs":[
		\\  {"host":"api.example.com","style":"bearer","secret":"api-token","stub":"spec-stub-keeps"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(gpa);
	try renderL7Inject(gpa, io, parsed.value, "zig-inject-test-no-global", inst_dir, &out, &hosts);
	const s = out.items;

	// Unchanged from before this feature: the spec's style + its own stub are used,
	// and the claude sentinel is NOT stamped onto a non-claude kind.
	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"bearer\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "spec-stub-keeps") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, secret_mod.claude_stub_token) == null);
	try std.testing.expect(std.mem.indexOf(u8, s, "anthropic-oauth") == null);
}

test "seedClaudeInject gates strictly on BOTH enforcer-private secret-dir overrides" {
	// Container enforcer/worker: both set -> seed. VM boot render / non-enforcing
	// agent: neither (or only one, which never happens) set -> no seed.
	try std.testing.expect(seedClaudeInject("/run/cogbox-secrets/global", "/run/cogbox-secrets/instance"));
	try std.testing.expect(!seedClaudeInject(null, "/run/cogbox-secrets/instance"));
	try std.testing.expect(!seedClaudeInject("/run/cogbox-secrets/global", null));
	try std.testing.expect(!seedClaudeInject(null, null));
}

test "seedClaudeInjectSpec seeds the claude-oauth spec into l7.inject.specs (idempotent)" {
	const gpa = std.testing.allocator;
	// A rules-mode network with NO l7 yet (the container default before the seed).
	const src =
		\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;

	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 1), specs.items.len);
	const s0 = specs.items[0].object;
	try std.testing.expectEqualStrings(secret_mod.anthropic_api_host, s0.get("host").?.string);
	try std.testing.expectEqualStrings(secret_mod.anthropic_oauth_kind, s0.get("style").?.string);
	try std.testing.expectEqualStrings(secret_mod.claude_oauth_secret, s0.get("secret").?.string);
	// A spec only NAMES a credential: no value/path/stub leaks into config.
	try std.testing.expect(s0.get("stub") == null);
	try std.testing.expect(s0.get("cred_file") == null);

	// Idempotent: re-seeding the same network adds nothing.
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
	const specs2 = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 1), specs2.items.len);
}

test "seedClaudeInjectSpec is additive: keeps an existing plugin inject spec" {
	const gpa = std.testing.allocator;
	// A plugin already contributed a spec for a different host (OSS-clean fictionals).
	const src =
		\\{"l7":{"inject":{"specs":[
		\\  {"host":"api.example.com","style":"bearer","secret":"api-token","plugin":"obs-plugin"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;

	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs.items.len);
	// the plugin spec is untouched (still first)
	try std.testing.expectEqualStrings("api.example.com", specs.items[0].object.get("host").?.string);
	try std.testing.expectEqualStrings("obs-plugin", specs.items[0].object.get("plugin").?.string);
	// the harness claude spec was appended
	try std.testing.expectEqualStrings(secret_mod.anthropic_api_host, specs.items[1].object.get("host").?.string);
	try std.testing.expectEqualStrings(secret_mod.claude_oauth_secret, specs.items[1].object.get("secret").?.string);
}

test "seeded claude-oauth spec: renderL7Inject silent when unbound, emits when bound" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	// The container default: a rules-mode network with no l7 -> seed it, exactly as
	// the enforcer render does before writing the inject conf.
	const src =
		\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	// Unbound: claude-oauth isn't in the store -> renderL7Inject emits NO element
	// and routes NO host, the fail-closed "guest carries its own token" fallback.
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		var hosts: std.ArrayList(u8) = .empty;
		defer hosts.deinit(gpa);
		try renderL7Inject(gpa, io, net, "zig-inject-test-no-global", inst_dir, &out, &hosts);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "anthropic-oauth") == null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, secret_mod.anthropic_api_host) == null);
		try std.testing.expect(std.mem.indexOf(u8, hosts.items, secret_mod.anthropic_api_host) == null);
	}

	// Bind the reserved secret the way cogworx's reconcile does: kind=anthropic-oauth,
	// audience pinned to the host. The VALUE is a fictional (OSS-clean) setup-token.
	try secret_store.add(gpa, io, inst_dir, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// Bound: the seeded spec now resolves -> an anthropic-oauth element carrying the
	// shared stub sentinel, NO refresh block, and the host mirrored into the
	// plain-HTTP inject-routing list.
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		var hosts: std.ArrayList(u8) = .empty;
		defer hosts.deinit(gpa);
		try renderL7Inject(gpa, io, net, "zig-inject-test-no-global", inst_dir, &out, &hosts);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "\"style\": \"anthropic-oauth\"") != null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "\"cred_format\": \"raw\"") != null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, secret_mod.claude_stub_token) != null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "refresh") == null);
		try std.testing.expect(std.mem.indexOf(u8, hosts.items, secret_mod.anthropic_api_host) != null);
	}
}

test "claudeOAuthBound: false when unbound, true once the claude-oauth secret is bound" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	var arena = std.heap.ArenaAllocator.init(gpa);
	defer arena.deinit();

	// Never connected: nothing in the store -> not bound.
	try std.testing.expect(!(try claudeOAuthBound(arena.allocator(), io, inst_dir, "zig-inject-test-no-global")));

	// Connect (the reconcile's bind). Now bound.
	try secret_store.add(gpa, io, inst_dir, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	try std.testing.expect(try claudeOAuthBound(arena.allocator(), io, inst_dir, "zig-inject-test-no-global"));
}

test "gap #1: renderL7 terminate-allows api.anthropic.com ONLY when the seed is applied (bound)" {
	const gpa = std.testing.allocator;

	// UNBOUND -> the seed is NOT applied (main.zig gates seedClaudeInjectSpec on
	// claudeOAuthBound), so the container default network carries no claude spec and
	// renderL7 must NOT terminate-allow api.anthropic.com (the L4 deny-list governs).
	{
		const src =
			\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
		;
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderL7(gpa, parsed.value, &out);
		try std.testing.expect(std.mem.indexOf(u8, out.items, secret_mod.anthropic_api_host) == null);
	}

	// BOUND -> the seed IS applied; renderL7 then terminate-allows the host so the
	// injected Bearer can be stamped on a MITM-terminated flow.
	{
		const src =
			\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
		;
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var net = parsed.value;
		try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderL7(gpa, net, &out);
		var allow_buf: [64]u8 = undefined;
		const allow_line = std.fmt.bufPrint(&allow_buf, "allow {s} terminate", .{secret_mod.anthropic_api_host}) catch unreachable;
		try std.testing.expect(std.mem.indexOf(u8, out.items, allow_line) != null);
	}
}

test "gap #2: seed is shadow-safe -- appends when a DIFFERENT secret already claims the host" {
	const gpa = std.testing.allocator;
	// A plugin spec already targets api.anthropic.com under a DIFFERENT secret name.
	// The old idempotency check (host-only) would have skipped, silently shadowing
	// the per-user bind. The guard must append the claude-oauth spec anyway.
	const src =
		\\{"l7":{"inject":{"specs":[
		\\  {"host":"api.anthropic.com","style":"bearer","secret":"plugin-anthropic","plugin":"obs-plugin"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;

	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs.items.len);
	// the plugin spec is untouched (still first, still its own secret)
	try std.testing.expectEqualStrings("plugin-anthropic", specs.items[0].object.get("secret").?.string);
	// the per-user bind STILL renders: our claude-oauth spec was appended
	try std.testing.expectEqualStrings(secret_mod.claude_oauth_secret, specs.items[1].object.get("secret").?.string);
	try std.testing.expectEqualStrings(secret_mod.anthropic_api_host, specs.items[1].object.get("host").?.string);

	// True idempotency is preserved: re-seeding now that OUR secret names the host
	// adds nothing (only our own seed -- not a foreign spec -- suppresses a re-add).
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
	const specs2 = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs2.items.len);
}
