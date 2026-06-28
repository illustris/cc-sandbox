// `cogbox secret` - bind/list/remove operator-held credentials in the global
// host-side secret store (<config>/secrets/). Plugins REQUEST a secret by name
// + audience (cogboxPlugins.<attr>.inject); the operator binds the value here so
// it stays host-side and out of the guest. Mirrors verbs/l7.zig's shape but
// resolves the GLOBAL store (no --name), since operator secrets are shared
// across an account's instances.
//
// Binding/removing a secret changes which credentials are injectable, but the
// per-instance inject conf the running L7 proxy reads (l7-inject-conf.json) is
// only rendered at boot. So when an instance is named with -n, after the
// mutation we re-render THAT instance's runtime files (rules_module.renderFiles,
// which calls writeL7Inject) and SIGHUP its proxy, so a bind takes effect on a
// RUNNING VM without a restart -- the addon hot-reloads the conf on mtime.
// `cogbox secret reload -n NAME` does only the re-render (no store change), for a
// secret that was already bound (e.g. before this behavior existed).

const std = @import("std");
const help = @import("../help.zig");
const parse = @import("../parse.zig");
const util = @import("../util.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const secret_module = @import("secret_module");
const rules_module = @import("rules_module");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	// Pull out -n/--name and -h/--help; the rest is the secret subcommand. The
	// secret store itself is global (no -n), but -n names the instance whose
	// inject conf to re-render after a mutation.
	var name: ?[]const u8 = null;
	var rest: std.ArrayList([]const u8) = .empty;
	defer rest.deinit(allocator);

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
			try help.print(io, help.SECRET);
			return;
		}
		if (std.mem.eql(u8, a, "--name") or std.mem.eql(u8, a, "-n")) {
			i += 1;
			if (i >= argv.len) util.die(allocator, io, "secret", exit_codes.usage, "{s} requires a value", .{a});
			name = argv[i];
			continue;
		}
		if (std.mem.startsWith(u8, a, "--name=")) {
			name = a[7..];
			continue;
		}
		if (std.mem.startsWith(u8, a, "-n=")) {
			name = a[3..];
			continue;
		}
		try rest.append(allocator, a);
	}

	if (name) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "secret", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "secret", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
	}

	// `secret reload -n NAME`: re-render an instance's inject conf from the
	// already-bound store + signal its proxy. No store mutation.
	if (rest.items.len > 0 and std.mem.eql(u8, rest.items[0], "reload")) {
		const n = name orelse util.die(allocator, io, "secret", exit_codes.usage, "secret reload requires -n NAME", .{});
		try reRenderInstance(allocator, io, env, p, n, true);
		return;
	}

	// The store the operator binds into. The container enforcer keeps it on an
	// ENFORCER-PRIVATE volume (never the agent-readable PVC), so honor the same
	// COGBOX_GLOBAL_SECRETS_DIR override the renderer (resolveSecretDirs) reads;
	// otherwise the historical <config>/secrets is used. WRITE and READ must
	// agree on one location, else a bind would render against the wrong store.
	const secrets_dir = if (env.get("COGBOX_GLOBAL_SECRETS_DIR")) |d|
		try allocator.dupe(u8, d)
	else
		try paths.globalSecretsDir(allocator, p);
	defer allocator.free(secrets_dir);

	try secret_module.dispatch(allocator, io, secrets_dir, rest.items);

	// After a bind/remove that changes injectable state, re-render the named
	// instance so a running proxy picks it up without a restart. Best-effort:
	// the store mutation already succeeded, so a render failure (instance not
	// running / not inited) must not fail the command.
	if (name) |n| {
		if (rest.items.len > 0 and isMutation(rest.items[0])) {
			reRenderInstance(allocator, io, env, p, n, false) catch |err| {
				util.warn(allocator, io, "secret bound, but re-rendering {s}'s inject conf failed ({s}); it will apply on the instance's next start", .{ n, @errorName(err) }) catch {};
			};
		}
	}
}

fn isMutation(sub: []const u8) bool {
	return std.mem.eql(u8, sub, "add") or std.mem.eql(u8, sub, "rm") or
		std.mem.eql(u8, sub, "del") or std.mem.eql(u8, sub, "delete");
}

/// Re-render instance `name`'s runtime files (incl. l7-inject-conf.json) from
/// its config + the now-current secret store, then SIGHUP its L7 proxy. Skips
/// quietly when the instance isn't inited or isn't running (no live runtime dir)
/// -- the boot render covers that case. `announce` adds a user-facing line (for
/// the explicit `reload` verb).
fn reRenderInstance(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, p: *const paths.Paths, name: []const u8, announce: bool) !void {
	const inst_cfg = try paths.instanceConfigDir(allocator, p, name);
	defer allocator.free(inst_cfg);
	const cfg_path = try std.fs.path.join(allocator, &.{ inst_cfg, "config.json" });
	defer allocator.free(cfg_path);
	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const cwd = std.Io.Dir.cwd();
	cwd.access(io, cfg_path, .{}) catch {
		if (announce) try util.say(allocator, io, "No config for '{s}' -- nothing to render.", .{name});
		return;
	};
	// No live runtime dir => the instance isn't running; the boot render will
	// pick up the binding on next start.
	cwd.access(io, inst_runtime, .{}) catch {
		if (announce) try util.say(allocator, io, "Instance '{s}' is not running; inject conf will render at its next start.", .{name});
		return;
	};

	try rules_module.renderFiles(allocator, io, env, cfg_path, inst_runtime);
	_ = rules_module.reload.maybeSignalL7proxy(allocator, io, inst_runtime) catch {};
	if (announce) try util.say(allocator, io, "Re-rendered inject conf for '{s}' and signalled its proxy.", .{name});
}
