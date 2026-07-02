// `cogbox plugin` verb dispatcher. Manages the `.plugins` array in
// config.json: each entry is a flake (resolved + pinned by nix at add time)
// whose cogboxPlugins.<attr>.module gets folded into the guest via the generated
// composition flake. A plugin may also suggest firewall rules through the
// optional `cogboxPlugins.<attr>.networkRules` flake output; those merge into
// .network.rules tagged with the plugin's name (shown for confirmation, and
// removed/replaced exactly by del/update).
//
// Module changes need an instance restart; merged rules hot-reload through
// the shared rules_module path like every other rules-table edit.

const std = @import("std");
const builtin_mod = @import("builtin");
pub const cli = @import("cli.zig");
pub const name_mod = @import("name.zig");
pub const compose = @import("compose.zig");
pub const mutate = @import("mutate.zig");
pub const nix = @import("nix.zig");
pub const gitcred = @import("gitcred.zig");

const rules_module = @import("rules_module");
const config = rules_module.config;
const rule = rules_module.rule;
const l7_module = @import("l7_module");
const l7_rule = l7_module.rule;

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *const std.process.Environ.Map,
	instance: ?[]const u8,
	config_path: []const u8,
	runtime_path: []const u8,
	user_flake_dir: []const u8,
	plugins_flake_dir: []const u8,
	rest: []const []const u8,
) !void {
	const cmd = cli.parse(rest) catch |err| {
		const msg = switch (err) {
			error.MissingSubcommand => "missing subcommand (list, add, del, update, resolve)",
			error.UnknownSubcommand => "unknown subcommand (expected list, add, del, update, resolve)",
			error.MissingUrl => "add requires a FLAKE_URL",
			error.MissingPlugin => "del requires a plugin name",
			error.InvalidArgs => "invalid arguments",
		};
		die(allocator, io, "{s}", .{msg}, 64);
	};

	var loaded = config.load(allocator, io, config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	// plugin-sources/ and plugin-cache/ are SIBLINGS of plugins-flake/ (under
	// the instance config dir): putting them INSIDE plugins-flake/ would change
	// the composition flake's source hash. plugins-flake/ holds only flake.nix
	// + flake.lock. plugin-sources/<name>/ is the materialized (writable) copy
	// of each plugin's source, referenced as a path: input; plugin-cache/ is a
	// file:// binary cache for the launch-time substituter.
	const instance_config_dir = std.fs.path.dirname(plugins_flake_dir) orelse ".";
	const sources_dir = try std.fs.path.join(allocator, &.{ instance_config_dir, "plugin-sources" });
	defer allocator.free(sources_dir);
	const cache_dir = try std.fs.path.join(allocator, &.{ instance_config_dir, "plugin-cache" });
	defer allocator.free(cache_dir);

	var ctx: Ctx = .{
		.allocator = allocator,
		.io = io,
		.parent_env = env,
		.instance = instance,
		.config_path = config_path,
		.runtime_path = runtime_path,
		.user_flake_dir = user_flake_dir,
		.plugins_flake_dir = plugins_flake_dir,
		.sources_dir = sources_dir,
		.cache_dir = cache_dir,
	};

	switch (cmd) {
		.list => try cmdList(&ctx, &loaded),
		.add => |a| try cmdAdd(&ctx, &loaded, a),
		.del => |d| try cmdDel(&ctx, &loaded, d),
		.update => |u| try cmdUpdate(&ctx, &loaded, u),
		.resolve => |r| try cmdResolve(&ctx, &loaded, r),
	}
}

// --- resolve (truthful pre-install preview; no mutation) -----------------

// cmdResolve previews a flake URL the way cmdAdd's read-only prefix does --
// flake metadata + the cogboxPlugins.<attr> contract check + the host-side
// networkRules/l7Rules/inject readout -- and emits ONE JSON line on stdout for
// the control plane (cogworx's Backend.ResolvePin). It installs nothing: no
// config mutation, no source materialization, no composition regen. Human
// chatter routes to stderr (the defer_rules flag) so stdout carries only JSON.
fn cmdResolve(ctx: *Ctx, loaded: *config.Loaded, r: cli.ResolveArgs) !void {
	_ = loaded;
	const allocator = ctx.allocator;
	const io = ctx.io;
	ctx.defer_rules = true;

	var fetch_env: ?gitcred.FetchEnv = null;
	defer if (fetch_env) |*fe| fe.deinit();
	if (r.git_credential_stdin) {
		const raw = gitcred.readStdin(allocator, io) catch {
			die(allocator, io, "could not read git credential from stdin", .{}, 65);
		};
		defer allocator.free(raw);
		const cred = gitcred.parseLine(raw) catch {
			die(allocator, io, "malformed git credential on stdin (want host<TAB>user<TAB>token)", .{}, 65);
		};
		fetch_env = gitcred.FetchEnv.setup(allocator, io, ctx.parent_env, cred) catch {
			die(allocator, io, "could not set up authenticated fetch", .{}, 70);
		};
		ctx.fetch_env = fetch_env.?.map();
	}

	const split = name_mod.splitFragment(r.url) catch |err| switch (err) {
		error.EmptyFragment => die(allocator, io, "empty #fragment in '{s}'", .{r.url}, 65),
		error.InvalidAttr => die(allocator, io, "invalid module attr in '{s}' (allowed: [a-zA-Z0-9_-])", .{r.url}, 65),
	};
	const ref = split.ref;
	const attr: ?[]const u8 = if (split.attr) |sa|
		(if (std.mem.eql(u8, sa, "default")) null else sa)
	else
		null;

	// Best-effort name (preview only): from the attr, else the URL, else "plugin".
	const name: []const u8 = blk: {
		if (attr) |at| break :blk name_mod.deriveNameFromAttr(allocator, at) catch try allocator.dupe(u8, "plugin");
		break :blk name_mod.deriveName(allocator, ref) catch try allocator.dupe(u8, "plugin");
	};
	defer allocator.free(name);

	try announce(ctx, "Resolving '{s}'...", .{ref});
	var meta = resolveFlake(ctx, ref);
	defer meta.deinit(allocator);
	const dirty = meta.rev == null and nix.isGitOrHgUrl(meta.locked_url);

	const module_attr = attr orelse "default";
	const present = switch (try nix.evalHasCogboxPlugin(allocator, io, ctx.fetch_env, meta.locked_url, module_attr)) {
		.present => true,
		.missing => false,
		.failed => |stderr| die(allocator, io, "could not evaluate flake '{s}':\n{s}", .{ meta.locked_url, nix.stderrTail(stderr) }, 65),
	};

	// Host-side policy readout (only meaningful when the contract is present).
	var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l4_parsed) |*p| p.deinit();
	var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l7_parsed) |*p| p.deinit();
	var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (inject_parsed) |*p| p.deinit();
	var l4: []const std.json.Value = &.{};
	var l7: []const std.json.Value = &.{};
	var inject: []const std.json.Value = &.{};
	if (present) {
		l4_parsed = evalRules(ctx, meta.locked_url, attr);
		if (l4_parsed) |p| l4 = p.value.array.items;
		l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
		if (l7_parsed) |p| l7 = p.value.array.items;
		inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
		if (inject_parsed) |p| inject = p.value.array.items;
	}

	const line = try renderResolveJson(allocator, name, attr, ref, &meta, dirty, present, l4, l7, inject);
	defer allocator.free(line);
	try writeStdout(io, line);
}

/// Build the one-line resolve JSON the control plane consumes:
///   {"name","attr","url","lockedUrl","rev","narHash","dirty","present",
///    "networkRules":[...],"l7Rules":[...],"inject":[...]}
/// The rule/inject objects are the SAME validated shapes evalRules/evalL7Rules/
/// evalInjectSpecs produced. Caller frees.
fn renderResolveJson(
	allocator: std.mem.Allocator,
	name: []const u8,
	attr: ?[]const u8,
	url: []const u8,
	meta: *const nix.Meta,
	dirty: bool,
	present: bool,
	l4: []const std.json.Value,
	l7: []const std.json.Value,
	inject: []const std.json.Value,
) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try out.appendSlice(allocator, "{\"name\":");
	try writeCompactString(allocator, &out, name);
	try out.appendSlice(allocator, ",\"attr\":");
	try writeCompactString(allocator, &out, attr orelse "default");
	try out.appendSlice(allocator, ",\"url\":");
	try writeCompactString(allocator, &out, url);
	try out.appendSlice(allocator, ",\"lockedUrl\":");
	try writeCompactString(allocator, &out, meta.locked_url);
	try out.appendSlice(allocator, ",\"rev\":");
	if (meta.rev) |rev| try writeCompactString(allocator, &out, rev) else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, ",\"narHash\":");
	try writeCompactString(allocator, &out, meta.nar_hash);
	try out.appendSlice(allocator, ",\"dirty\":");
	try out.appendSlice(allocator, if (dirty) "true" else "false");
	try out.appendSlice(allocator, ",\"present\":");
	try out.appendSlice(allocator, if (present) "true" else "false");
	try out.appendSlice(allocator, ",\"networkRules\":");
	try writeCompactArray(allocator, &out, l4);
	try out.appendSlice(allocator, ",\"l7Rules\":");
	try writeCompactArray(allocator, &out, l7);
	try out.appendSlice(allocator, ",\"inject\":");
	try writeCompactArray(allocator, &out, inject);
	try out.appendSlice(allocator, "}\n");
	return out.toOwnedSlice(allocator);
}

const Ctx = struct {
	allocator: std.mem.Allocator,
	io: std.Io,
	// The parent environment, used to clone a per-fetch env when a credential
	// is supplied. The nix fetch otherwise inherits this unchanged.
	parent_env: *const std.process.Environ.Map,
	instance: ?[]const u8,
	config_path: []const u8,
	runtime_path: []const u8,
	user_flake_dir: []const u8,
	plugins_flake_dir: []const u8,
	// Siblings of plugins_flake_dir (see dispatch): plugin-sources/ holds the
	// materialized writable source of each plugin (referenced as a path: input
	// so launch resolves it offline); plugin-cache/ is the file:// binary cache
	// the launcher uses as an extra substituter for transitive inputs.
	sources_dir: []const u8,
	cache_dir: []const u8,
	// Per-fetch credential env. null => the nix
	// fetch runs with the inherited parent env (public/unauthenticated). When a
	// `--git-credential-stdin` add/update supplies a token, cmdAdd/cmdUpdate set
	// this to the temp-netrc env for the duration of the fetch, then tear it down.
	fetch_env: ?*const std.process.Environ.Map = null,
	// --defer-rules: when true, every human announce() is redirected to STDERR so
	// the only thing on STDOUT is the one `{"deferred":...}` JSON line cmdAdd
	// emits. The control plane parses that line; routing chatter to stderr keeps
	// it clean. Set by cmdAdd for the duration of a deferred add.
	defer_rules: bool = false,
};

// --- list ---------------------------------------------------------------

fn cmdList(ctx: *const Ctx, loaded: *config.Loaded) !void {
	const arr = mutate.existingPluginsArray(loaded.root());
	if (arr == null or arr.?.items.len == 0) {
		try announce(ctx, "(no plugins)", .{});
		return;
	}

	const rules_arr = rulesOrNull(loaded);
	const l7_arr = l7RulesOrNull(loaded);
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(ctx.allocator);

	for (arr.?.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse "?";
		const u = mutate.entryField(item.object, "url") orelse "?";
		const rules_n = (if (rules_arr) |ra| mutate.countTaggedRules(ra, n) else 0) +
			(if (l7_arr) |la| mutate.countTaggedRules(la, n) else 0);
		const frag: []const u8 = if (mutate.entryField(item.object, "attr")) |a| a else "";
		const line = try std.fmt.allocPrint(
			ctx.allocator,
			"{s}  {s}{s}{s}  rev={s}  rules={d}\n",
			.{ n, u, if (frag.len > 0) "#" else "", frag, shortRev(item.object), rules_n },
		);
		defer ctx.allocator.free(line);
		try out.appendSlice(ctx.allocator, line);
	}
	try writeStdout(ctx.io, out.items);
}

/// Display pin: short rev when there is one, else a narHash prefix
/// (dirty path: flakes have no rev).
fn shortRev(obj: std.json.ObjectMap) []const u8 {
	if (mutate.entryField(obj, "rev")) |r| {
		return r[0..@min(r.len, 7)];
	}
	if (mutate.entryField(obj, "narHash")) |h| {
		const stripped = if (std.mem.startsWith(u8, h, "sha256-")) h[7..] else h;
		return stripped[0..@min(stripped.len, 8)];
	}
	return "?";
}

// --- add ----------------------------------------------------------------

fn cmdAdd(ctx: *Ctx, loaded: *config.Loaded, a: cli.AddArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	// Under --defer-rules every human announce()/warn() routes to stderr so the
	// only thing on stdout is the one deferred-rules JSON line emitted at the end.
	ctx.defer_rules = a.defer_rules;

	// --git-credential-stdin: read the one credential line, materialize a temp
	// 0600 netrc + clear-helper gitconfig, and scope a per-fetch env to it for
	// every nix call below. Torn down (temp dir removed) when this verb returns.
	// The token is never in argv/env-of-record/log; it lives only in the temp
	// netrc for the lifetime of the fetch.
	var fetch_env: ?gitcred.FetchEnv = null;
	defer if (fetch_env) |*fe| fe.deinit();
	if (a.git_credential_stdin) {
		const raw = gitcred.readStdin(allocator, io) catch {
			die(allocator, io, "could not read git credential from stdin", .{}, 65);
		};
		defer allocator.free(raw);
		const cred = gitcred.parseLine(raw) catch {
			die(allocator, io, "malformed git credential on stdin (want host<TAB>user<TAB>token)", .{}, 65);
		};
		fetch_env = gitcred.FetchEnv.setup(allocator, io, ctx.parent_env, cred) catch {
			die(allocator, io, "could not set up authenticated fetch", .{}, 70);
		};
		ctx.fetch_env = fetch_env.?.map();
	}

	// `URL#attr` selects cogboxPlugins.<attr>; bare URL means `default`.
	const split = name_mod.splitFragment(a.url) catch |err| switch (err) {
		error.EmptyFragment => die(allocator, io, "empty #fragment in '{s}'", .{a.url}, 65),
		error.InvalidAttr => die(allocator, io, "invalid module attr in '{s}' (allowed: [a-zA-Z0-9_-])", .{a.url}, 65),
	};
	const ref = split.ref;
	// An explicit `#default` is the same as no fragment.
	const attr: ?[]const u8 = if (split.attr) |sa|
		(if (std.mem.eql(u8, sa, "default")) null else sa)
	else
		null;

	const plugin_name: []const u8 = blk: {
		if (a.as) |as| {
			if (!name_mod.isValidPluginName(as)) {
				die(allocator, io, "invalid plugin name '{s}' (must start with a letter, [a-zA-Z0-9-], max 64; 'user' is reserved)", .{as}, 65);
			}
			break :blk try allocator.dupe(u8, as);
		}
		if (attr) |at| {
			break :blk name_mod.deriveNameFromAttr(allocator, at) catch {
				die(allocator, io, "cannot derive a plugin name from attr '{s}'; pass --as NAME", .{at}, 65);
			};
		}
		break :blk name_mod.deriveName(allocator, ref) catch {
			die(allocator, io, "cannot derive a plugin name from '{s}'; pass --as NAME", .{ref}, 65);
		};
	};
	defer allocator.free(plugin_name);

	const plugins_arr = mutate.pluginsArray(loaded.root(), loaded.treeAllocator()) catch {
		die(allocator, io, "invalid JSON in {s} (.plugins is not an array)", .{ctx.config_path}, 65);
	};
	if (mutate.findPlugin(plugins_arr, plugin_name) != null) {
		die(allocator, io, "plugin '{s}' already exists (choose another name with --as)", .{plugin_name}, 65);
	}

	// Flake-level versioning: if another module of this same flake URL is
	// already installed, reuse its pin instead of resolving the tip again,
	// so all plugins from one flake stay at one rev (`update` moves them
	// together). A different rev can still be forced by pinning it in the
	// URL itself, which makes the URL string distinct.
	var meta: nix.Meta = blk: {
		if (mutate.findByUrl(plugins_arr, ref)) |sibling| {
			const locked = mutate.entryField(sibling.object, "lockedUrl");
			const hash = mutate.entryField(sibling.object, "narHash");
			if (locked != null and hash != null) {
				try announce(ctx, "Reusing pin of installed flake '{s}' ({s}).", .{ ref, shortRev(sibling.object) });
				break :blk .{
					.locked_url = try allocator.dupe(u8, locked.?),
					.rev = if (mutate.entryField(sibling.object, "rev")) |r| try allocator.dupe(u8, r) else null,
					.nar_hash = try allocator.dupe(u8, hash.?),
					// No metadata call on this path: resolve the source store
					// path lazily via flakeSourcePath when we materialize.
					.source_path = try allocator.dupe(u8, ""),
				};
			}
		}
		try announce(ctx, "Resolving '{s}'...", .{ref});
		break :blk resolveFlake(ctx, ref);
	};
	defer meta.deinit(allocator);

	// A git/hg lock without a rev is a dirty worktree: the locked URL can't
	// carry a narHash (the fetcher would hand it to the remote) and has no
	// rev, so nothing pins it -- the guest module floats with the worktree
	// across restarts.
	if (meta.rev == null and nix.isGitOrHgUrl(meta.locked_url)) {
		try warn(ctx, "source tree is dirty: the lock has no rev, so the plugin floats with the worktree (commit, then `cogbox plugin update`, to pin)", .{});
	}

	const module_attr = attr orelse "default";
	switch (try nix.evalHasCogboxPlugin(allocator, io, ctx.fetch_env, meta.locked_url, module_attr)) {
		.present => {},
		.missing => die(allocator, io, "plugin flake does not expose cogboxPlugins.{s} (see docs/plugins.md)", .{module_attr}, 65),
		.failed => |stderr| die(allocator, io, "could not evaluate flake '{s}':\n{s}", .{ meta.locked_url, nix.stderrTail(stderr) }, 65),
	}

	// Materialize the plugin source onto the PVC so the composition can point
	// a path: input at it (offline at launch -- the git+ URL needs a token we
	// don't have at start). Done here, under the still-authenticated fetch env,
	// so the source store path is already realized. Best-effort: on failure the
	// composition falls back to the locked URL (has_source=false).
	materializeSource(ctx, plugin_name, &meta, ref) catch |err| {
		warn(ctx, "could not materialize plugin source (launch may need network): {s}", .{@errorName(err)}) catch {};
	};

	archiveFlake(ctx, meta.locked_url);

	// Optional plugin contributions: L4 CIDR + L7 vhost rules, plus credential
	// injection requests -- one confirmation. Injection gets its own louder
	// section: granting a host-side credential is a different kind of trust
	// than a firewall rule.
	var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l4_parsed) |*p| p.deinit();
	const incoming_l4: []const std.json.Value = blk: {
		l4_parsed = evalRules(ctx, meta.locked_url, attr);
		const p = l4_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};
	var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l7_parsed) |*p| p.deinit();
	const incoming_l7: []const std.json.Value = blk: {
		l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
		const p = l7_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};
	var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (inject_parsed) |*p| p.deinit();
	const incoming_inject: []const std.json.Value = blk: {
		inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
		const p = inject_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};

	// --defer-rules: withhold the plugin's L4/L7 networkRules from config.json and
	// report them on stdout instead (the control plane routes them through admin
	// approval). The module install and the inject-spec merge are UNCHANGED:
	// injection is a separate trust class, gated host-side by `secret bind`, so it
	// keeps its own confirm/merge path. The withheld L4/L7 rules count zero toward
	// the prompt below; only inject specs prompt under defer.
	const merge_l4 = if (a.defer_rules) &[_]std.json.Value{} else incoming_l4;
	const merge_l7 = if (a.defer_rules) &[_]std.json.Value{} else incoming_l7;

	var merged = false;
	var merged_inject = false;
	const total = merge_l4.len + merge_l7.len + incoming_inject.len;
	if (total > 0) {
		if (rulesOrNull(loaded)) |rules_arr| {
			if (merge_l4.len + merge_l7.len > 0) {
				try announce(ctx, "Suggested network rules from '{s}':", .{plugin_name});
				for (merge_l4) |r| try printRuleLine(ctx, "+", r);
				for (merge_l7) |r| try printL7RuleLine(ctx, "+", r);
			}
			if (incoming_inject.len > 0) {
				try announce(ctx, "Credential injection requests from '{s}' (host-side; the secret stays OUT of the guest):", .{plugin_name});
				for (incoming_inject) |s| try printInjectLine(ctx, "+", s);
			}
			const prompt = try std.fmt.allocPrint(allocator, "Apply these {d} change(s) at the top of the lists?", .{total});
			defer allocator.free(prompt);
			// Under defer the confirm prompt is suppressed (stdout stays the JSON
			// line; the deferred rules are not applied here regardless).
			if (!a.yes and !a.defer_rules and !try confirm(ctx, prompt)) {
				try announce(ctx, "Aborted.", .{});
				return;
			}
			if (merge_l4.len > 0) {
				try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, plugin_name, merge_l4);
			}
			if (merge_l7.len > 0) {
				const l7_arr = try ensureL7Rules(loaded);
				try mutate.prependTaggedRules(loaded.treeAllocator(), l7_arr, plugin_name, merge_l7);
			}
			if (incoming_inject.len > 0) {
				const inj_arr = try ensureInjectSpecs(loaded);
				try mutate.prependTaggedRules(loaded.treeAllocator(), inj_arr, plugin_name, incoming_inject);
				merged_inject = true;
			}
			merged = true;
		} else {
			try warn(ctx, "instance is not in rules mode; skipping {d} suggested change(s)", .{total});
		}
	}

	try mutate.appendPlugin(loaded.treeAllocator(), plugins_arr, .{
		.name = plugin_name,
		.url = ref,
		.attr = attr,
		.locked_url = meta.locked_url,
		.rev = meta.rev,
		.nar_hash = meta.nar_hash,
	});

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	finalizeComposition(ctx);
	if (merged) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' added at {s}.", .{ plugin_name, pinLabel(&meta) });
	if (merged_inject) try printBindChecklist(ctx, incoming_inject);
	try printRestartHint(ctx, "to load its NixOS module");

	// Under --defer-rules emit the withheld L4/L7 rules as one JSON line on
	// stdout (the ONLY stdout output; all human chatter went to stderr). The
	// control plane parses this and files one admin-approval request per rule.
	if (a.defer_rules) {
		const line = try renderDeferredJson(allocator, plugin_name, incoming_l4, incoming_l7);
		defer allocator.free(line);
		try writeStdout(io, line);
	}
}

/// Build the one-line deferred-rules JSON the control plane consumes:
///   {"deferred":{"plugin":"<name>","l4":[<L4 rule objects>],"l7":[<L7 rule objects>]}}
/// The rule objects are the SAME validated shapes evalRules/evalL7Rules produced
/// (so the control plane never re-encodes CIDR/host semantics), serialized
/// compactly on a single line. Caller frees. Pure (testable) function.
fn renderDeferredJson(
	allocator: std.mem.Allocator,
	plugin_name: []const u8,
	l4: []const std.json.Value,
	l7: []const std.json.Value,
) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try out.appendSlice(allocator, "{\"deferred\":{\"plugin\":");
	try writeCompactString(allocator, &out, plugin_name);
	try out.appendSlice(allocator, ",\"l4\":");
	try writeCompactArray(allocator, &out, l4);
	try out.appendSlice(allocator, ",\"l7\":");
	try writeCompactArray(allocator, &out, l7);
	try out.appendSlice(allocator, "}}\n");
	return out.toOwnedSlice(allocator);
}

fn writeCompactArray(allocator: std.mem.Allocator, out: *std.ArrayList(u8), items: []const std.json.Value) std.mem.Allocator.Error!void {
	try out.append(allocator, '[');
	for (items, 0..) |item, i| {
		if (i > 0) try out.append(allocator, ',');
		try writeCompactValue(allocator, out, item);
	}
	try out.append(allocator, ']');
}

/// Compact (no-whitespace, single-line) JSON serializer for a std.json.Value.
/// Mirrors config.writeJqTab's escaping but emits no indentation/newlines, so
/// the deferred line parses as exactly one line.
fn writeCompactValue(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: std.json.Value) std.mem.Allocator.Error!void {
	switch (value) {
		.null => try out.appendSlice(allocator, "null"),
		.bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
		.integer => |i| {
			var buf: [32]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
			try out.appendSlice(allocator, s);
		},
		.float => |f| {
			var buf: [64]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{f}) catch unreachable;
			try out.appendSlice(allocator, s);
		},
		.number_string => |s| try out.appendSlice(allocator, s),
		.string => |s| try writeCompactString(allocator, out, s),
		.array => |arr| try writeCompactArray(allocator, out, arr.items),
		.object => |obj| {
			try out.append(allocator, '{');
			var it = obj.iterator();
			var i: usize = 0;
			while (it.next()) |entry| {
				if (i > 0) try out.append(allocator, ',');
				try writeCompactString(allocator, out, entry.key_ptr.*);
				try out.append(allocator, ':');
				try writeCompactValue(allocator, out, entry.value_ptr.*);
				i += 1;
			}
			try out.append(allocator, '}');
		},
	}
}

fn writeCompactString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	try out.append(allocator, '"');
	for (s) |c| {
		switch (c) {
			'"' => try out.appendSlice(allocator, "\\\""),
			'\\' => try out.appendSlice(allocator, "\\\\"),
			'\n' => try out.appendSlice(allocator, "\\n"),
			'\r' => try out.appendSlice(allocator, "\\r"),
			'\t' => try out.appendSlice(allocator, "\\t"),
			0x08 => try out.appendSlice(allocator, "\\b"),
			0x0c => try out.appendSlice(allocator, "\\f"),
			0...0x07, 0x0b, 0x0e...0x1f => {
				var buf: [8]u8 = undefined;
				const esc = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch unreachable;
				try out.appendSlice(allocator, esc);
			},
			else => try out.append(allocator, c),
		}
	}
	try out.append(allocator, '"');
}

// --- del ----------------------------------------------------------------

fn cmdDel(ctx: *const Ctx, loaded: *config.Loaded, d: cli.DelArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	const plugins_arr = mutate.existingPluginsArray(loaded.root()) orelse {
		die(allocator, io, "no such plugin '{s}'", .{d.plugin}, 65);
	};
	const idx = mutate.findPlugin(plugins_arr, d.plugin) orelse {
		die(allocator, io, "no such plugin '{s}'", .{d.plugin}, 65);
	};

	const rules_arr = rulesOrNull(loaded);
	const l7_arr = l7RulesOrNull(loaded);
	const inject_arr = injectSpecsOrNull(loaded);
	const tagged = (if (rules_arr) |ra| mutate.countTaggedRules(ra, d.plugin) else 0) +
		(if (l7_arr) |la| mutate.countTaggedRules(la, d.plugin) else 0) +
		(if (inject_arr) |ia| mutate.countTaggedRules(ia, d.plugin) else 0);

	const prompt = try std.fmt.allocPrint(allocator, "Remove plugin '{s}' and its {d} contributed rule(s)/inject spec(s)?", .{ d.plugin, tagged });
	defer allocator.free(prompt);
	if (!d.yes and !try confirm(ctx, prompt)) {
		try announce(ctx, "Aborted.", .{});
		return;
	}

	_ = plugins_arr.orderedRemove(idx);
	var removed = if (rules_arr) |ra| mutate.removeTaggedRules(ra, d.plugin) else 0;
	removed += if (l7_arr) |la| mutate.removeTaggedRules(la, d.plugin) else 0;
	removed += if (inject_arr) |ia| mutate.removeTaggedRules(ia, d.plugin) else 0;

	// Drop the materialized source for the removed plugin so it stops being a
	// path: input and its disk space is reclaimed.
	removeSource(ctx, d.plugin);

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	// No fetch needed: remaining inputs are local path: refs. Best-effort.
	finalizeComposition(ctx);
	if (removed > 0) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' removed ({d} contributed entr(ies) dropped).", .{ d.plugin, removed });
	try printRestartHint(ctx, "to unload its NixOS module");
}

// --- update -------------------------------------------------------------

fn cmdUpdate(ctx: *Ctx, loaded: *config.Loaded, u: cli.UpdateArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	// --git-credential-stdin: same single-fetch netrc setup as add. update
	// re-resolves the flake (nix flake metadata + archive), so the private repo
	// needs the acting user's token for those fetches too.
	var fetch_env: ?gitcred.FetchEnv = null;
	defer if (fetch_env) |*fe| fe.deinit();
	if (u.git_credential_stdin) {
		const raw = gitcred.readStdin(allocator, io) catch {
			die(allocator, io, "could not read git credential from stdin", .{}, 65);
		};
		defer allocator.free(raw);
		const cred = gitcred.parseLine(raw) catch {
			die(allocator, io, "malformed git credential on stdin (want host<TAB>user<TAB>token)", .{}, 65);
		};
		fetch_env = gitcred.FetchEnv.setup(allocator, io, ctx.parent_env, cred) catch {
			die(allocator, io, "could not set up authenticated fetch", .{}, 70);
		};
		ctx.fetch_env = fetch_env.?.map();
	}

	const plugins_arr = mutate.existingPluginsArray(loaded.root()) orelse {
		if (u.plugin) |p| die(allocator, io, "no such plugin '{s}'", .{p}, 65);
		try announce(ctx, "(no plugins)", .{});
		return;
	};
	if (u.plugin) |p| {
		if (mutate.findPlugin(plugins_arr, p) == null) {
			die(allocator, io, "no such plugin '{s}'", .{p}, 65);
		}
	} else if (plugins_arr.items.len == 0) {
		try announce(ctx, "(no plugins)", .{});
		return;
	}

	var changed = false;
	var rules_touched = false;
	var failed = false;

	// Versioning is per flake: resolve each distinct URL once per run and
	// apply the same pin to every plugin that came from it, so siblings
	// can't drift apart across an update.
	var resolved: std.ArrayList(struct { url: []const u8, meta: nix.Meta }) = .empty;
	defer {
		for (resolved.items) |*r| r.meta.deinit(allocator);
		resolved.deinit(allocator);
	}

	for (plugins_arr.items) |*item| {
		if (item.* != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse {
			try warn(ctx, "skipping malformed plugin entry (no name)", .{});
			failed = true;
			continue;
		};
		if (u.plugin) |p| {
			if (!std.mem.eql(u8, p, n)) continue;
		}
		const url = mutate.entryField(item.object, "url") orelse {
			try warn(ctx, "{s}: malformed entry (no url); re-add it", .{n});
			failed = true;
			continue;
		};
		const attr = mutate.entryField(item.object, "attr");
		if (attr) |at| {
			if (!name_mod.isValidAttr(at)) {
				try warn(ctx, "{s}: malformed entry (bad attr); re-add it", .{n});
				failed = true;
				continue;
			}
		}
		const old_hash = mutate.entryField(item.object, "narHash") orelse "";

		const meta: *nix.Meta = blk: {
			for (resolved.items) |*r| {
				if (std.mem.eql(u8, r.url, url)) break :blk &r.meta;
			}
			// --refresh: bypass nix's flake eval cache so a mutable ref re-resolves
			// to the current tip. Without it, update can keep returning the cached
			// rev and never actually move the pin.
			var meta_out = nix.flakeMetadata(allocator, io, ctx.fetch_env, url, true) catch {
				die(allocator, io, "failed to run nix (is it on PATH?)", .{}, 70);
			};
			defer meta_out.deinit(allocator);
			if (!meta_out.ok) {
				try warn(ctx, "{s}: could not resolve '{s}': {s}", .{ n, url, nix.stderrTail(meta_out.stderr) });
				failed = true;
				break :blk null;
			}
			const m = nix.parseMetadata(allocator, meta_out.stdout) catch {
				try warn(ctx, "{s}: unexpected nix flake metadata output", .{n});
				failed = true;
				break :blk null;
			};
			try resolved.append(allocator, .{ .url = url, .meta = m });
			break :blk &resolved.items[resolved.items.len - 1].meta;
		} orelse continue;

		if (std.mem.eql(u8, meta.nar_hash, old_hash)) {
			try announce(ctx, "{s}: up to date ({s})", .{ n, pinLabel(meta) });
			continue;
		}

		// Re-materialize this plugin's source at the new rev so its path: input
		// tracks the update (offline at launch). `url` is the original ref, used
		// only as the lazy fallback for flakeSourcePath. Best-effort.
		materializeSource(ctx, n, meta, url) catch |err| {
			warn(ctx, "{s}: could not materialize plugin source (launch may need network): {s}", .{ n, @errorName(err) }) catch {};
		};

		archiveFlake(ctx, meta.locked_url);

		var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (l4_parsed) |*p| p.deinit();
		const incoming_l4: []const std.json.Value = blk: {
			l4_parsed = evalRules(ctx, meta.locked_url, attr);
			const p = l4_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};
		var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (l7_parsed) |*p| p.deinit();
		const incoming_l7: []const std.json.Value = blk: {
			l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
			const p = l7_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};
		var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (inject_parsed) |*p| p.deinit();
		const incoming_inject: []const std.json.Value = blk: {
			inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
			const p = inject_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};

		if (rulesOrNull(loaded)) |rules_arr| {
			const old_l7 = l7RulesOrNull(loaded);
			const old_inject = injectSpecsOrNull(loaded);
			const old_count = mutate.countTaggedRules(rules_arr, n) +
				(if (old_l7) |la| mutate.countTaggedRules(la, n) else 0) +
				(if (old_inject) |ia| mutate.countTaggedRules(ia, n) else 0);
			if (old_count > 0 or incoming_l4.len + incoming_l7.len + incoming_inject.len > 0) {
				try announce(ctx, "{s}: contributed rules + inject specs", .{n});
				for (rules_arr.items) |r| {
					if (mutate.ruleTag(r)) |tag| {
						if (std.mem.eql(u8, tag, n)) try printRuleLine(ctx, "-", r);
					}
				}
				if (old_l7) |la| {
					for (la.items) |r| {
						if (mutate.ruleTag(r)) |tag| {
							if (std.mem.eql(u8, tag, n)) try printL7RuleLine(ctx, "-", r);
						}
					}
				}
				if (old_inject) |ia| {
					for (ia.items) |r| {
						if (mutate.ruleTag(r)) |tag| {
							if (std.mem.eql(u8, tag, n)) try printInjectLine(ctx, "-", r);
						}
					}
				}
				for (incoming_l4) |r| try printRuleLine(ctx, "+", r);
				for (incoming_l7) |r| try printL7RuleLine(ctx, "+", r);
				for (incoming_inject) |s| try printInjectLine(ctx, "+", s);
				_ = mutate.removeTaggedRules(rules_arr, n);
				try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, n, incoming_l4);
				if (old_l7) |la| _ = mutate.removeTaggedRules(la, n);
				if (incoming_l7.len > 0) {
					const l7_arr = try ensureL7Rules(loaded);
					try mutate.prependTaggedRules(loaded.treeAllocator(), l7_arr, n, incoming_l7);
				}
				if (old_inject) |ia| _ = mutate.removeTaggedRules(ia, n);
				if (incoming_inject.len > 0) {
					const inj_arr = try ensureInjectSpecs(loaded);
					try mutate.prependTaggedRules(loaded.treeAllocator(), inj_arr, n, incoming_inject);
				}
				rules_touched = true;
			}
		} else if (incoming_l4.len + incoming_l7.len + incoming_inject.len > 0) {
			try warn(ctx, "{s}: instance is not in rules mode; skipping {d} suggested change(s)", .{ n, incoming_l4.len + incoming_l7.len + incoming_inject.len });
		}

		try mutate.relockPlugin(loaded.treeAllocator(), item, .{
			.name = n,
			.url = url,
			.locked_url = meta.locked_url,
			.rev = meta.rev,
			.nar_hash = meta.nar_hash,
		});
		changed = true;
		try announce(ctx, "{s}: updated to {s}", .{ n, pinLabel(meta) });
	}

	if (changed) {
		try config.save(allocator, io, ctx.config_path, loaded.root().*);
		if (rules_touched) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);
	}
	// Regenerate even without changes: update doubles as the self-heal for
	// a missing/stale composition flake (it is a pure function of config +
	// on-disk sources).
	try regenComposition(ctx, plugins_arr);
	finalizeComposition(ctx);
	if (changed) try printRestartHint(ctx, "to load the updated NixOS modules");
	if (failed) std.process.exit(65);
}

// --- shared helpers ------------------------------------------------------

/// nix flake metadata + parse, with fatal errors on failure.
fn resolveFlake(ctx: *const Ctx, url: []const u8) nix.Meta {
	var out = nix.flakeMetadata(ctx.allocator, ctx.io, ctx.fetch_env, url, false) catch {
		die(ctx.allocator, ctx.io, "failed to run nix (is it on PATH?)", .{}, 70);
	};
	defer out.deinit(ctx.allocator);
	if (!out.ok) {
		die(ctx.allocator, ctx.io, "could not resolve flake '{s}':\n{s}", .{ url, nix.stderrTail(out.stderr) }, 65);
	}
	return nix.parseMetadata(ctx.allocator, out.stdout) catch {
		die(ctx.allocator, ctx.io, "unexpected nix flake metadata output for '{s}'", .{url}, 70);
	};
}

/// Pre-fetch the plugin and its transitive inputs into the store so later
/// (offline) starts resolve the pinned URLs locally. Failure is non-fatal:
/// the plugin still works, the first start just needs network.
fn archiveFlake(ctx: *const Ctx, locked_url: []const u8) void {
	var out = nix.flakeArchive(ctx.allocator, ctx.io, ctx.fetch_env, locked_url) catch return;
	defer out.deinit(ctx.allocator);
	if (!out.ok) {
		warn(ctx, "could not pre-fetch flake inputs (offline starts may fail): {s}", .{nix.stderrTail(out.stderr)}) catch {};
	}
}

/// Whether the plugin's source has been materialized -- the marker that lets
/// render emit a path: input. For a subdir flake (`?dir=`) the flake.nix lives
/// at <sources_dir>/<name>/<dir>/flake.nix (the materialized tree is the repo
/// root); `dir` null means the repo root.
fn sourceHydrated(ctx: *const Ctx, name: []const u8, dir: ?[]const u8) bool {
	const cwd = std.Io.Dir.cwd();
	const flake = std.fs.path.join(ctx.allocator, &.{ ctx.sources_dir, name, dir orelse ".", "flake.nix" }) catch return false;
	defer ctx.allocator.free(flake);
	cwd.access(ctx.io, flake, .{}) catch return false;
	return true;
}

/// Copy a plugin's locked source tree onto the PVC at <sources_dir>/<name>/ as
/// a WRITABLE directory, so the composition can reference it as a `path:` input
/// that launch resolves offline (no fetcher, no credential). The store source
/// path is read-only, so the copy is reset to writable modes.
///
/// `meta.source_path` is used when present (the metadata path); otherwise (the
/// cmdAdd sibling-reuse path, which built Meta WITHOUT a metadata call) the
/// store path is resolved lazily via `flakeSourcePath` for `url`, under the
/// authenticated fetch env. An empty resolved path is a hard error (the caller
/// downgrades it to a warning and falls back to the locked URL).
fn materializeSource(ctx: *const Ctx, name: []const u8, meta: *const nix.Meta, url: []const u8) !void {
	const allocator = ctx.allocator;

	var owned_src: ?[]u8 = null;
	defer if (owned_src) |s| allocator.free(s);
	const src: []const u8 = blk: {
		if (meta.source_path.len > 0) break :blk meta.source_path;
		owned_src = try nix.flakeSourcePath(allocator, ctx.io, ctx.fetch_env, url);
		break :blk owned_src.?;
	};
	if (src.len == 0) return error.NoSourcePath;

	const dest = try std.fs.path.join(allocator, &.{ ctx.sources_dir, name });
	defer allocator.free(dest);

	const cwd = std.Io.Dir.cwd();
	try cwd.createDirPath(ctx.io, ctx.sources_dir);
	// Replace any prior copy so a downgrade/re-add can't leave stale files.
	cwd.deleteTree(ctx.io, dest) catch {};

	// Recursive copy with writable reset. Coreutils are present in the pod
	// image (the launcher already uses cp/mv/rm); a native walk would have to
	// re-implement mode reset for read-only store trees. `cp -a SRC/. DEST`
	// copies SRC's contents into DEST (DEST is the plugin's own dir);
	// --no-preserve drops the store's read-only modes, and chmod then forces
	// u+w across the tree so a later deleteTree/replace and nix's path: read
	// both work.
	const src_dot = try std.fmt.allocPrint(allocator, "{s}/.", .{src});
	defer allocator.free(src_dot);
	try runTool(ctx, &.{ "cp", "-a", "--no-preserve=mode,ownership", src_dot, dest });
	try runTool(ctx, &.{ "chmod", "-R", "u+rwX", dest });
}

/// Remove a plugin's materialized source dir (del path). Best-effort.
fn removeSource(ctx: *const Ctx, name: []const u8) void {
	const dest = std.fs.path.join(ctx.allocator, &.{ ctx.sources_dir, name }) catch return;
	defer ctx.allocator.free(dest);
	std.Io.Dir.cwd().deleteTree(ctx.io, dest) catch {};
}

/// Run a host tool (cp/chmod), inheriting the parent env so PATH resolves the
/// coreutils binaries. Errors if the tool can't run or exits non-zero.
fn runTool(ctx: *const Ctx, argv: []const []const u8) !void {
	const res = try std.process.run(ctx.allocator, ctx.io, .{ .argv = argv, .environ_map = null });
	defer {
		ctx.allocator.free(res.stdout);
		ctx.allocator.free(res.stderr);
	}
	if (res.term != .exited or res.term.exited != 0) return error.ToolFailed;
}

/// After regenerating the composition: reconcile its flake.lock and populate
/// the launch-time binary cache. Both are best-effort (warn, never die): the
/// lock makes launch deterministic (resolved from a coherent pin, offline for
/// path: inputs), and the cache substitutes any transitive tarball/narHash
/// input on a fresh store. Skipped when no composition exists (no plugins).
fn finalizeComposition(ctx: *const Ctx) void {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();

	// Only run when the composition flake actually exists.
	const flake = std.fs.path.join(allocator, &.{ ctx.plugins_flake_dir, "flake.nix" }) catch return;
	defer allocator.free(flake);
	cwd.access(ctx.io, flake, .{}) catch return;

	const flake_url = std.fmt.allocPrint(allocator, "path:{s}", .{ctx.plugins_flake_dir}) catch return;
	defer allocator.free(flake_url);

	// Reconcile/write the lock so launch resolves deterministically offline.
	if (nix.flakeLock(allocator, ctx.io, ctx.fetch_env, flake_url)) |out| {
		var o = out;
		defer o.deinit(allocator);
		if (!o.ok) warn(ctx, "could not lock composition (launch may re-resolve inputs): {s}", .{nix.stderrTail(o.stderr)}) catch {};
	} else |_| {}

	// Populate the file:// binary cache the launcher uses as a substituter.
	const cache_url = std.fmt.allocPrint(allocator, "file://{s}", .{ctx.cache_dir}) catch return;
	defer allocator.free(cache_url);
	if (nix.flakeArchiveTo(allocator, ctx.io, ctx.fetch_env, cache_url, flake_url)) |out| {
		var o = out;
		defer o.deinit(allocator);
		if (!o.ok) warn(ctx, "could not populate offline plugin cache (transitive inputs may need network at launch): {s}", .{nix.stderrTail(o.stderr)}) catch {};
	} else |_| {}

	// Pre-build the microvm runner and push it to the configured remote cache so
	// boot SUBSTITUTES it instead of rebuilding the expensive closure from source.
	// Gated on cogworx opting in via env;
	// best-effort throughout -- a failure here only means boot rebuilds, never a
	// failed plugin verb.
	prebuildAndPushRunner(ctx);

	// Container backend counterpart: pre-build cogbox-brain (which now carries the
	// plugins' cogbox.packages as $out/bin) and copy its closure into the LOCAL
	// per-instance plugin-cache, so the agent's egress-less boot substitutes it
	// offline instead of failing to build the plugin tools. Gated on
	// COGBOX_BRAIN_PUSH_LOCAL (the container backend); a no-op on the VM.
	prebuildBrainLocal(ctx);
}

/// The env-driven runner pre-build + push (Stage 1 of the offline-launch
/// optimization). Runs only when cogworx (the worker pod) requests it:
/// COGBOX_RUNNER_PUSH == "1" AND COGBOX_PUSH_CONFIG is set. It builds the SAME
/// microvm runner the boot path would build (identical flake ref +
/// --override-input set => byte-identical out-path; nothing instance-specific
/// is in the closure -- hostname/ports/keys are launch-time sed rewrites on the
/// OUTPUT), then pushes that out-path's closure to the cache so a fresh-store
/// boot substitutes it. Every failure is logged and swallowed.
fn prebuildAndPushRunner(ctx: *const Ctx) void {
	const allocator = ctx.allocator;
	const env = ctx.parent_env;

	const push = env.get("COGBOX_RUNNER_PUSH") orelse return;
	if (!std.mem.eql(u8, push, "1")) return;
	const push_config = env.get("COGBOX_PUSH_CONFIG") orelse return;
	if (push_config.len == 0) return;

	// The cogbox flake + nixpkgs store paths, baked by mkCogbox (--set-default).
	const flake_source = env.get("COGBOX_FLAKE_SOURCE") orelse {
		warn(ctx, "runner push: COGBOX_FLAKE_SOURCE unset; skipping pre-build", .{}) catch {};
		return;
	};
	const nixpkgs_source = env.get("COGBOX_NIXPKGS_SOURCE") orelse {
		warn(ctx, "runner push: COGBOX_NIXPKGS_SOURCE unset; skipping pre-build", .{}) catch {};
		return;
	};

	// The config-name suffix: cogbox-x86_64 / cogbox-aarch64. builtin.cpu.arch
	// is fixed at compile time to the arch this cogbox image was built for, and
	// its tag name (x86_64 / aarch64) matches flake.nix's archSuffix exactly.
	const arch = @tagName(builtin_mod.cpu.arch);

	// Combine the per-instance file:// cache with cogworx's remote substituters
	// so the runner's transitive deps substitute rather than build from source.
	const extra_subs = env.get("COGBOX_EXTRA_SUBSTITUTERS") orelse "";
	const substituters = blk: {
		if (extra_subs.len == 0) break :blk std.fmt.allocPrint(allocator, "file://{s}", .{ctx.cache_dir}) catch return;
		break :blk std.fmt.allocPrint(allocator, "file://{s} {s}", .{ ctx.cache_dir, extra_subs }) catch return;
	};
	defer allocator.free(substituters);

	const out = nix.buildRunner(allocator, ctx.io, env, .{
		.flake_source = flake_source,
		.nixpkgs_source = nixpkgs_source,
		.plugins_flake_dir = ctx.plugins_flake_dir,
		.arch = arch,
		.substituters = substituters,
		.trusted_public_keys = env.get("COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS") orelse "",
		.netrc_file = env.get("COGBOX_NETRC_FILE") orelse "",
	}) catch {
		warn(ctx, "runner push: build failed to launch (boot will rebuild)", .{}) catch {};
		return;
	};
	var o = out;
	defer o.deinit(allocator);
	if (!o.ok) {
		warn(ctx, "runner push: build failed (boot will rebuild): {s}", .{nix.stderrTail(o.stderr)}) catch {};
		return;
	}
	// --print-out-paths emits the store path(s), one per line; take the first.
	const out_path = std.mem.trim(u8, o.stdout, " \t\r\n");
	const first = if (std.mem.indexOfScalar(u8, out_path, '\n')) |i| out_path[0..i] else out_path;
	if (first.len == 0) {
		warn(ctx, "runner push: build produced no out-path (boot will rebuild)", .{}) catch {};
		return;
	}

	const pushed = pushToCache(ctx, push_config, first);

	// Pre-write the launcher's skip-eval fast-path record so a FRESH instance's
	// FIRST boot fast-paths instead of paying the ~18min --override-input eval.
	// Normally that record ($INSTANCE_CONFIG_DIR/runner.path) is written only by
	// a prior eval boot (cogbox-launch.sh); a brand-new instance would have to
	// eval once. Since we already built the composed runner and pushed it here,
	// record it now so the very first boot realises it from the cache (a fetch,
	// no eval). We ONLY record after a successful push: on a new instance the
	// persistent /nix is empty, so the launcher's fast path runs
	// `nix-store --realise` to fetch the recorded runner from the cache -- a
	// record pointing at a closure that never made it into the cache would make
	// that realise fail (the launcher then falls back to eval, so it's still
	// safe, but recording it would be pointless). The rev marker we write is
	// flake_source, which equals the launcher's baked @flakeSource@ (both the
	// worker pod and the sandbox launcher run the SAME cogbox image, so the same
	// COGBOX_FLAKE_SOURCE / @flakeSource@ store path) -- the marker therefore
	// matches and the record self-heals across image bumps (a stale rev simply
	// fails the launcher's `[ "$FP_REV" = "@flakeSource@" ]` guard and re-evals).
	if (pushed) writeRunnerRecord(ctx, flake_source, first);
}

/// The container backend's local brain pre-build (the offline-boot counterpart
/// of prebuildAndPushRunner). Runs only when cogworx's container backend requests
/// it: COGBOX_BRAIN_PUSH_LOCAL == "1". Unlike the VM path there is NO remote push
/// and NO runner.path record -- the container's cogbox-brain-materialize always
/// evaluates then substitutes. It builds the SAME cogbox-brain out-path the
/// container boot evaluates (identical flake ref + --override-input set; the brain
/// now carries the plugins' cogbox.packages as $out/bin), then `nix copy`s that
/// out-path's closure into the LOCAL per-instance plugin-cache (file://cache_dir,
/// on the state PVC). The agent's boot has no egress, so without this seed the
/// brain rebuild cannot realise the plugin tools; with it, boot substitutes the
/// whole closure offline. Every failure is logged and swallowed (boot then falls
/// back to the baked base brain -- skills survive, tools are simply absent, i.e.
/// no worse than before this fix). Determinism mirrors the runner path: nothing
/// instance-specific is in the brain closure, so the pre-built out-path is
/// byte-identical to the one boot's brainResolveContainer evaluates.
fn prebuildBrainLocal(ctx: *const Ctx) void {
	const allocator = ctx.allocator;
	const env = ctx.parent_env;

	const local = env.get("COGBOX_BRAIN_PUSH_LOCAL") orelse return;
	if (!std.mem.eql(u8, local, "1")) return;

	// The cogbox flake + nixpkgs store paths, baked by mkCogbox (--set-default)
	// into the same cogbox image the container boot evaluates against.
	const flake_source = env.get("COGBOX_FLAKE_SOURCE") orelse {
		warn(ctx, "brain prebuild: COGBOX_FLAKE_SOURCE unset; skipping (boot rebuilds)", .{}) catch {};
		return;
	};
	const nixpkgs_source = env.get("COGBOX_NIXPKGS_SOURCE") orelse {
		warn(ctx, "brain prebuild: COGBOX_NIXPKGS_SOURCE unset; skipping (boot rebuilds)", .{}) catch {};
		return;
	};

	// cogbox-x86_64 / cogbox-aarch64: the config-name suffix (compile-time arch,
	// matching flake.nix's archSuffix), same derivation as the runner path.
	const arch = @tagName(builtin_mod.cpu.arch);

	// Combine the per-instance file:// cache with any remote substituters so the
	// brain's transitive nixpkgs deps (e.g. the plugin tools' closure) substitute
	// rather than build from source at add-time.
	const extra_subs = env.get("COGBOX_EXTRA_SUBSTITUTERS") orelse "";
	const substituters = blk: {
		if (extra_subs.len == 0) break :blk std.fmt.allocPrint(allocator, "file://{s}", .{ctx.cache_dir}) catch return;
		break :blk std.fmt.allocPrint(allocator, "file://{s} {s}", .{ ctx.cache_dir, extra_subs }) catch return;
	};
	defer allocator.free(substituters);

	const out = nix.buildBrain(allocator, ctx.io, env, .{
		.flake_source = flake_source,
		.nixpkgs_source = nixpkgs_source,
		.plugins_flake_dir = ctx.plugins_flake_dir,
		.arch = arch,
		.substituters = substituters,
		.trusted_public_keys = env.get("COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS") orelse "",
		.netrc_file = env.get("COGBOX_NETRC_FILE") orelse "",
	}) catch {
		warn(ctx, "brain prebuild: build failed to launch (boot rebuilds)", .{}) catch {};
		return;
	};
	var o = out;
	defer o.deinit(allocator);
	if (!o.ok) {
		warn(ctx, "brain prebuild: build failed (boot rebuilds): {s}", .{nix.stderrTail(o.stderr)}) catch {};
		return;
	}
	// --print-out-paths emits the store path(s), one per line; take the first.
	const out_path = std.mem.trim(u8, o.stdout, " \t\r\n");
	const first = if (std.mem.indexOfScalar(u8, out_path, '\n')) |i| out_path[0..i] else out_path;
	if (first.len == 0) {
		warn(ctx, "brain prebuild: build produced no out-path (boot rebuilds)", .{}) catch {};
		return;
	}

	// Seed the per-instance plugin-cache with the realized closure so boot
	// substitutes it (require-sigs false on the read side -- flake.nix
	// brainResolveContainer). Local file:// dest, no signing/push config needed.
	const cache_url = std.fmt.allocPrint(allocator, "file://{s}", .{ctx.cache_dir}) catch return;
	defer allocator.free(cache_url);
	if (nix.copyClosureTo(allocator, ctx.io, env, cache_url, first)) |cp| {
		var c = cp;
		defer c.deinit(allocator);
		if (!c.ok) warn(ctx, "brain prebuild: copy to plugin-cache failed (boot rebuilds): {s}", .{nix.stderrTail(c.stderr)}) catch {};
	} else |_| {
		warn(ctx, "brain prebuild: copy to plugin-cache failed to launch (boot rebuilds)", .{}) catch {};
	}
}

/// Best-effort pre-write of cogbox-launch.sh's runner.path fast-path record.
/// The file lives at <instance_config_dir>/runner.path on the shared state PVC
/// (the worker pod mounts it at the SAME XDG_CONFIG_HOME the sandbox launcher
/// does), where instance_config_dir = dirname(plugins_flake_dir). Contents must
/// byte-match what the launcher writes/reads: `printf '%s\n%s\n' <rev> <runner>`
/// -- two newline-terminated lines, line1 = the flakeSource (image rev) marker,
/// line2 = the composed runner out-path. Written atomically (tmp + rename) so a
/// partial write can't leave a half-record the launcher would misread; any
/// failure is warned and swallowed (a missing/short record just makes the first
/// boot fall back to eval, never a failed verb).
fn writeRunnerRecord(ctx: *const Ctx, flake_source: []const u8, runner: []const u8) void {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();

	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse {
		warn(ctx, "runner push: plugins-flake dir has no parent; skipping record (boot will eval)", .{}) catch {};
		return;
	};
	const path = std.fs.path.join(allocator, &.{ instance_config_dir, "runner.path" }) catch return;
	defer allocator.free(path);
	const tmp_path = std.fmt.allocPrint(allocator, "{s}.tmp", .{path}) catch return;
	defer allocator.free(tmp_path);

	const contents = std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ flake_source, runner }) catch return;
	defer allocator.free(contents);

	{
		const f = cwd.createFile(ctx.io, tmp_path, .{ .truncate = true }) catch {
			warn(ctx, "runner push: could not write runner record (boot will eval)", .{}) catch {};
			return;
		};
		defer f.close(ctx.io);
		var write_buf: [512]u8 = undefined;
		var writer = f.writer(ctx.io, &write_buf);
		writer.interface.writeAll(contents) catch {
			warn(ctx, "runner push: could not write runner record (boot will eval)", .{}) catch {};
			return;
		};
		writer.flush() catch {
			warn(ctx, "runner push: could not write runner record (boot will eval)", .{}) catch {};
			return;
		};
		f.sync(ctx.io) catch {};
	}
	cwd.rename(tmp_path, cwd, path, ctx.io) catch {
		cwd.deleteFile(ctx.io, tmp_path) catch {};
		warn(ctx, "runner push: could not finalize runner record (boot will eval)", .{}) catch {};
		return;
	};
}

/// Push `out_path` (and its closure) to the attic cache described by the
/// config.toml at `config_path`. attic has no config-path env override; it
/// reads $XDG_CONFIG_HOME/attic/config.toml, so we stand up a throwaway
/// XDG_CONFIG_HOME whose attic/config.toml symlinks the supplied config, then
/// run `attic push <cache> <path>` (attic computes the closure by default).
/// The cache name comes from COGBOX_PUSH_CACHE (generic; the config's
/// default-server resolves the server) or defaults to "store". Best-effort;
/// returns true iff `attic push` exited 0 (every failure path returns false).
fn pushToCache(ctx: *const Ctx, config_path: []const u8, out_path: []const u8) bool {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();

	// Throwaway XDG_CONFIG_HOME/attic/config.toml -> config_path.
	const base = ctx.parent_env.get("TMPDIR") orelse "/tmp";
	var rnd: [12]u8 = undefined;
	ctx.io.random(&rnd);
	var hex: [24]u8 = undefined;
	_ = std.fmt.bufPrint(&hex, "{x}", .{&rnd}) catch unreachable;
	const xdg = std.fmt.allocPrint(allocator, "{s}/cogbox-attic-{s}", .{ base, hex }) catch return false;
	defer allocator.free(xdg);
	defer cwd.deleteTree(ctx.io, xdg) catch {};

	const attic_dir = std.fs.path.join(allocator, &.{ xdg, "attic" }) catch return false;
	defer allocator.free(attic_dir);
	cwd.createDirPath(ctx.io, attic_dir) catch {
		warn(ctx, "runner push: could not stage attic config dir (boot will rebuild)", .{}) catch {};
		return false;
	};
	const link = std.fs.path.join(allocator, &.{ attic_dir, "config.toml" }) catch return false;
	defer allocator.free(link);
	cwd.symLink(ctx.io, config_path, link, .{}) catch {
		warn(ctx, "runner push: could not link attic config (boot will rebuild)", .{}) catch {};
		return false;
	};

	const cache = ctx.parent_env.get("COGBOX_PUSH_CACHE") orelse "store";

	// Run attic with the staged XDG_CONFIG_HOME; clone the parent env so PATH
	// (attic lives next to git in the pod image) and any netrc/SSL vars survive.
	var env = cloneEnvMap(allocator, ctx.parent_env) catch return false;
	defer env.deinit();
	env.put("XDG_CONFIG_HOME", xdg) catch return false;

	const res = std.process.run(allocator, ctx.io, .{
		.argv = &.{ "attic", "push", cache, out_path },
		.environ_map = &env,
	}) catch {
		warn(ctx, "runner push: could not run attic (boot will rebuild)", .{}) catch {};
		return false;
	};
	defer {
		allocator.free(res.stdout);
		allocator.free(res.stderr);
	}
	if (res.term != .exited or res.term.exited != 0) {
		warn(ctx, "runner push: attic push failed (boot will rebuild): {s}", .{nix.stderrTail(res.stderr)}) catch {};
		return false;
	}
	return true;
}

/// Clone an Environ.Map (every key/value copied; Map.put dupes internally) so a
/// single child exec can run with an overridden variable without mutating ours.
fn cloneEnvMap(allocator: std.mem.Allocator, src: *const std.process.Environ.Map) !std.process.Environ.Map {
	var out = std.process.Environ.Map.init(allocator);
	errdefer out.deinit();
	const ks = src.keys();
	const vs = src.values();
	for (ks, vs) |k, v| try out.put(k, v);
	return out;
}

/// Evaluate one of the plugin's suggested-rule lists:
/// cogboxPlugins."<attr>".<leaf>, with the flat path cogboxPlugins.<leaf> as
/// fallback for the default module. Returns the parsed tree when the output
/// exists and is a JSON list; null when the flake doesn't declare it.
fn evalRuleList(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8, leaf: []const u8) ?std.json.Parsed(std.json.Value) {
	const allocator = ctx.allocator;
	var out = nix.evalPluginRules(allocator, ctx.io, ctx.fetch_env, locked_url, attr orelse "default", leaf) catch return null;
	if (!out.ok and attr == null and nix.stderrSaysMissingAttribute(out.stderr)) {
		// No cogboxPlugins.default -- fall back to the flat form.
		out.deinit(allocator);
		out = nix.evalPluginRules(allocator, ctx.io, ctx.fetch_env, locked_url, null, leaf) catch return null;
	}
	defer out.deinit(allocator);
	if (!out.ok) {
		if (!nix.stderrSaysMissingAttribute(out.stderr)) {
			warn(ctx, "could not read cogboxPlugins.{s}: {s}", .{ leaf, nix.stderrTail(out.stderr) }) catch {};
		}
		return null;
	}

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, out.stdout, .{}) catch {
		die(allocator, ctx.io, "cogboxPlugins.{s} did not evaluate to JSON", .{leaf}, 65);
	};
	if (parsed.value != .array) {
		die(allocator, ctx.io, "cogboxPlugins.{s} must be a list of rule objects", .{leaf}, 65);
	}
	return parsed;
}

/// L4 CIDR rules (cogboxPlugins.<attr>.networkRules), validated.
fn evalRules(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "networkRules") orelse return null;
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginRule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidCidr => "invalid CIDR",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugins.networkRules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// L7 vhost rules (cogboxPlugins.<attr>.l7Rules), validated with the same
/// constraints `l7 add` enforces.
fn evalL7Rules(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "l7Rules") orelse return null;
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginL7Rule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidHost => "invalid host pattern",
				error.BadPath => "path must be a string starting with /",
				error.BadFlag => "tier flags must be booleans",
				error.ConflictingTier => "passthrough excludes terminate/path/insecure_upstream",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugins.l7Rules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// Credential injection specs (cogboxPlugins.<attr>.inject), validated:
/// name-only, exact audience host, no inline secret material.
fn evalInjectSpecs(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "inject") orelse return null;
	for (parsed.value.array.items, 0..) |s, i| {
		mutate.validatePluginInjectSpec(s) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.MissingHost => "missing/empty host",
				error.InvalidHost => "invalid host pattern",
				error.WildcardHost => "host must be exact (no wildcard)",
				error.BadStyle => "style must be \"bearer\", \"cookie\", or \"basic\"",
				error.BadStub => "stub must be a string",
				error.MissingSecret => "missing secret name",
				error.BadSecretName => "secret name must be [A-Za-z0-9_-] (max 64)",
				error.MissingCookieName => "cookie style requires a non-empty cookieName",
				error.BadCookieName => "invalid cookieName",
				error.InlineSecretForbidden => "may not inline a value or a path (path/cred_file/token/refresh/...); name a secret instead",
				error.BadPort => "port must be an integer in 1..65535",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugins.inject[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// .network.l7.rules, created on demand (merge path; rules mode is already
/// established by the caller).
fn ensureL7Rules(loaded: *config.Loaded) !*std.json.Array {
	const net = try loaded.network();
	const l7 = try l7_module.ensureL7Object(net, loaded.treeAllocator());
	return &l7.object.getPtr("rules").?.array;
}

/// .network.l7.inject.specs, created on demand (merge path). Coerces a legacy
/// bool `.network.l7.inject` into the object form { enabled, specs } -- only
/// ever reached on an explicit `plugin add` that brings inject specs, so the
/// bool->object migration happens on a verb, never on a plain start/read.
fn ensureInjectSpecs(loaded: *config.Loaded) !*std.json.Array {
	const arena = loaded.treeAllocator();
	const net = try loaded.network();
	const l7 = try l7_module.ensureL7Object(net, arena);

	if (l7.object.getPtr("inject")) |inj| {
		if (inj.* == .bool) {
			const enabled = inj.bool;
			var obj: std.json.ObjectMap = .empty;
			try obj.put(arena, try arena.dupe(u8, "enabled"), .{ .bool = enabled });
			try obj.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
			try l7.object.put(arena, try arena.dupe(u8, "inject"), .{ .object = obj });
		}
	} else {
		var obj: std.json.ObjectMap = .empty;
		try obj.put(arena, try arena.dupe(u8, "enabled"), .{ .bool = true });
		try obj.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
		try l7.object.put(arena, try arena.dupe(u8, "inject"), .{ .object = obj });
	}

	const inj = l7.object.getPtr("inject").?;
	if (inj.* != .object) return error.InvalidJson;
	if (inj.object.getPtr("specs") == null) {
		try inj.object.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
	}
	if (inj.object.getPtr("specs").?.* != .array) return error.InvalidJson;
	return &inj.object.getPtr("specs").?.array;
}

/// .network.l7.inject.specs if it already exists (del/update/count path);
/// null when inject is absent or still in the legacy bool form.
fn injectSpecsOrNull(loaded: *config.Loaded) ?*std.json.Array {
	const net = loaded.network() catch return null;
	const l7 = net.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const inj = l7.object.getPtr("inject") orelse return null;
	if (inj.* != .object) return null;
	const specs = inj.object.getPtr("specs") orelse return null;
	if (specs.* != .array) return null;
	return &specs.array;
}

/// .network.l7.rules if it already exists; never creates it (del/list path).
fn l7RulesOrNull(loaded: *config.Loaded) ?*std.json.Array {
	const net = loaded.network() catch return null;
	const l7 = net.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const r = l7.object.getPtr("rules") orelse return null;
	if (r.* != .array) return null;
	return &r.array;
}

/// Regenerate (or remove, when no plugins are left) the composition flake
/// from the current .plugins array. Pure function of config.json, rebuilt on
/// every mutation, so a crash between config save and this write self-heals
/// on the next plugin command.
fn regenComposition(ctx: *const Ctx, plugins_arr: *std.json.Array) !void {
	const allocator = ctx.allocator;
	if (plugins_arr.items.len == 0) {
		try compose.removeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir);
		return;
	}

	var refs: std.ArrayList(compose.PluginRef) = .empty;
	defer refs.deinit(allocator);
	for (plugins_arr.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse continue;
		const locked = mutate.entryField(item.object, "lockedUrl") orelse continue;
		const attr = mutate.entryField(item.object, "attr") orelse "default";
		// The attr lands quoted inside the generated flake; never emit one
		// that fails the safe-charset check (hand-edited config).
		if (!name_mod.isValidAttr(attr)) continue;
		// The plugin's subdir, if it lives in one (`?dir=` on the locked URL);
		// the materialized source is the repo root, so both the hydration check
		// and the path: input use it.
		const dir = nix.dirParam(locked);
		// has_source is a pure filesystem check (the flake.nix under the
		// materialized source exists), so render stays a function of config +
		// on-disk sources and self-heals: a materialize that failed earlier just
		// keeps the locked URL until a later add/update succeeds.
		try refs.append(allocator, .{
			.name = n,
			.locked_url = locked,
			.attr = attr,
			.has_source = sourceHydrated(ctx, n, dir),
			.dir = dir,
		});
	}

	const rendered = compose.render(allocator, ctx.instance orelse "default", ctx.user_flake_dir, ctx.sources_dir, refs.items) catch |err| switch (err) {
		error.NoPlugins => {
			try compose.removeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir);
			return;
		},
		else => return err,
	};
	defer allocator.free(rendered);
	try compose.writeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir, rendered);
}

fn pinLabel(meta: *const nix.Meta) []const u8 {
	if (meta.rev) |r| return r[0..@min(r.len, 7)];
	const h = meta.nar_hash;
	const stripped = if (std.mem.startsWith(u8, h, "sha256-")) h[7..] else h;
	return stripped[0..@min(stripped.len, 8)];
}

fn printRuleLine(ctx: *const Ctx, sign: []const u8, r: std.json.Value) !void {
	if (r != .object) return;
	const p = rule.ruleAction(r.object) orelse return;
	const action = switch (p.action) {
		.allow => "allow",
		.deny => "deny",
	};
	if (rule.ruleComment(r.object)) |c| {
		try announce(ctx, "  {s} {s} {s}  # {s}", .{ sign, action, p.cidr, c });
	} else {
		try announce(ctx, "  {s} {s} {s}", .{ sign, action, p.cidr });
	}
}

fn printL7RuleLine(ctx: *const Ctx, sign: []const u8, r: std.json.Value) !void {
	if (r != .object) return;
	const p = l7_rule.ruleAction(r.object) orelse return;
	const action = switch (p.action) {
		.allow => "allow",
		.deny => "deny",
	};

	var suffix: std.ArrayList(u8) = .empty;
	defer suffix.deinit(ctx.allocator);
	var is_terminate = false;
	if (r.object.get("path")) |pv| {
		if (pv == .string) {
			try suffix.append(ctx.allocator, ' ');
			try suffix.appendSlice(ctx.allocator, pv.string);
			is_terminate = true;
		}
	}
	if (r.object.get("terminate")) |tv| {
		if (tv == .bool and tv.bool) is_terminate = true;
	}
	var is_insecure = false;
	if (r.object.get("insecure_upstream")) |iv| {
		if (iv == .bool and iv.bool) {
			is_insecure = true;
			is_terminate = true;
		}
	}
	var is_passthrough = false;
	if (r.object.get("passthrough")) |pv| {
		if (pv == .bool and pv.bool) is_passthrough = true;
	}
	if (is_passthrough) {
		try suffix.appendSlice(ctx.allocator, " [passthrough]");
	} else {
		if (is_terminate) try suffix.appendSlice(ctx.allocator, " [terminate]");
		if (is_insecure) try suffix.appendSlice(ctx.allocator, " [insecure]");
	}

	if (l7_rule.ruleComment(r.object)) |c| {
		try announce(ctx, "  {s} l7 {s} {s}{s}  # {s}", .{ sign, action, p.host, suffix.items, c });
	} else {
		try announce(ctx, "  {s} l7 {s} {s}{s}", .{ sign, action, p.host, suffix.items });
	}
}

fn printInjectLine(ctx: *const Ctx, sign: []const u8, s: std.json.Value) !void {
	if (s != .object) return;
	const host = blk: {
		const h = s.object.get("host") orelse return;
		if (h != .string) return;
		break :blk h.string;
	};
	const style = if (s.object.get("style")) |sv| (if (sv == .string) sv.string else "bearer") else "bearer";
	const secret = if (s.object.get("secret")) |sv| (if (sv == .string) sv.string else "?") else "?";
	// Show :port only when a non-standard one is declared, so the operator can
	// see the funnel will cover it (a bare host implies 80/443).
	var port_buf: [8]u8 = undefined;
	const port_sfx: []const u8 = if (s.object.get("port")) |pv|
		(if (pv == .integer) (std.fmt.bufPrint(&port_buf, ":{d}", .{pv.integer}) catch "") else "")
	else
		"";
	if (std.mem.eql(u8, style, "cookie")) {
		const cn = if (s.object.get("cookieName")) |cv| (if (cv == .string) cv.string else "?") else "?";
		try announce(ctx, "  {s} inject {s}{s} cookie({s}) secret={s}", .{ sign, host, port_sfx, cn, secret });
	} else {
		try announce(ctx, "  {s} inject {s}{s} {s} secret={s}", .{ sign, host, port_sfx, style, secret });
	}
}

/// After merging inject specs, tell the operator exactly which secrets to bind
/// host-side. We don't (yet) check bound state here -- the point is the
/// command to run; an unbound secret simply renders no conf and injection
/// stays inert (fail closed) until bound.
fn printBindChecklist(ctx: *const Ctx, specs: []const std.json.Value) !void {
	if (specs.len == 0) return;
	try announce(ctx, "Bind these secrets host-side so injection takes effect (they stay OUT of the guest):", .{});
	for (specs) |s| {
		if (s != .object) continue;
		const secret = if (s.object.get("secret")) |sv| (if (sv == .string) sv.string else continue) else continue;
		const host = if (s.object.get("host")) |hv| (if (hv == .string) hv.string else "?") else "?";
		const kind = if (s.object.get("style")) |sv| (if (sv == .string) sv.string else "bearer") else "bearer";
		try announce(ctx, "  cogbox secret add {s} --from-file FILE --audience {s} --kind {s}", .{ secret, host, kind });
	}
}

fn printRestartHint(ctx: *const Ctx, why: []const u8) !void {
	if (!isRunning(ctx)) {
		try announce(ctx, "It will take effect at the next start.", .{});
		return;
	}
	if (ctx.instance) |n| {
		try announce(ctx, "Restart the instance ('cogbox restart -n {s}') {s}.", .{ n, why });
	} else {
		try announce(ctx, "Restart the instance ('cogbox restart') {s}.", .{why});
	}
}

fn isRunning(ctx: *const Ctx) bool {
	const pid_path = std.fs.path.join(ctx.allocator, &.{ ctx.runtime_path, "pid" }) catch return false;
	defer ctx.allocator.free(pid_path);

	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(ctx.io, pid_path, .{}) catch return false;
	defer file.close(ctx.io);
	var buf: [64]u8 = undefined;
	var reader = file.reader(ctx.io, &buf);
	const text = reader.interface.allocRemaining(ctx.allocator, .limited(64)) catch return false;
	defer ctx.allocator.free(text);
	const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, text, " \t\r\n"), 10) catch return false;

	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	return true;
}

/// Interactive confirmation. Non-tty stdin auto-confirms, matching the
/// launcher's behavior for its own prompts (scripted/test use).
fn confirm(ctx: *const Ctx, prompt: []const u8) !bool {
	const stdin = std.Io.File.stdin();
	const tty = stdin.isTty(ctx.io) catch false;
	if (!tty) return true;

	const msg = try std.fmt.allocPrint(ctx.allocator, "{s} [y/N] ", .{prompt});
	defer ctx.allocator.free(msg);
	try writeStdout(ctx.io, msg);

	var buf: [256]u8 = undefined;
	var reader = stdin.readerStreaming(ctx.io, &buf);
	const line = (reader.interface.takeDelimiter('\n') catch return false) orelse return false;
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	return trimmed.len > 0 and (trimmed[0] == 'y' or trimmed[0] == 'Y');
}

fn rulesOrNull(loaded: *config.Loaded) ?*std.json.Array {
	return loaded.rules() catch null;
}

fn writeStdout(io: std.Io, bytes: []const u8) !void {
	const stdout = std.Io.File.stdout();
	var buf: [4096]u8 = undefined;
	var w = stdout.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn writeStderr(io: std.Io, bytes: []const u8) !void {
	const stderr = std.Io.File.stderr();
	var buf: [4096]u8 = undefined;
	var w = stderr.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn announce(ctx: *const Ctx, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(ctx.allocator, fmt ++ "\n", args);
	defer ctx.allocator.free(msg);
	// Under --defer-rules the only thing on stdout is the deferred-rules JSON
	// line; send all human chatter to stderr so that line parses cleanly.
	if (ctx.defer_rules) {
		try writeStderr(ctx.io, msg);
	} else {
		try writeStdout(ctx.io, msg);
	}
}

fn warn(ctx: *const Ctx, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(ctx.allocator, "cogbox plugin: warning: " ++ fmt ++ "\n", args);
	defer ctx.allocator.free(msg);
	try writeStderr(ctx.io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox plugin: error: " ++ fmt ++ "\n", args) catch "cogbox plugin: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}

// --- tests ---------------------------------------------------------------

const t = std.testing;

test "renderDeferredJson emits one line with the validated rule shapes" {
	const a = t.allocator;
	// The exact validated shapes evalRules/evalL7Rules produce: an L4 allow on a
	// CIDR, and an L7 deny on a host with a terminate flag + comment.
	var l4_parsed = try std.json.parseFromSlice(std.json.Value, a, "[{\"allow\":\"203.0.113.0/24\"}]", .{});
	defer l4_parsed.deinit();
	var l7_parsed = try std.json.parseFromSlice(std.json.Value, a, "[{\"deny\":\"api.example.com\",\"terminate\":true,\"comment\":\"x\"}]", .{});
	defer l7_parsed.deinit();

	const line = try renderDeferredJson(a, "obs-plugin", l4_parsed.value.array.items, l7_parsed.value.array.items);
	defer a.free(line);

	// Trailing newline, single line otherwise (no embedded newlines in the body).
	try t.expect(line.len > 0 and line[line.len - 1] == '\n');
	try t.expect(std.mem.indexOfScalar(u8, line[0 .. line.len - 1], '\n') == null);

	// It round-trips to the documented contract.
	var rt = try std.json.parseFromSlice(std.json.Value, a, line, .{});
	defer rt.deinit();
	const deferred = rt.value.object.get("deferred").?.object;
	try t.expectEqualStrings("obs-plugin", deferred.get("plugin").?.string);
	const l4 = deferred.get("l4").?.array;
	try t.expectEqual(@as(usize, 1), l4.items.len);
	try t.expectEqualStrings("203.0.113.0/24", l4.items[0].object.get("allow").?.string);
	const l7 = deferred.get("l7").?.array;
	try t.expectEqual(@as(usize, 1), l7.items.len);
	try t.expectEqualStrings("api.example.com", l7.items[0].object.get("deny").?.string);
	try t.expect(l7.items[0].object.get("terminate").?.bool);
	try t.expectEqualStrings("x", l7.items[0].object.get("comment").?.string);
}

test "renderDeferredJson with no rules emits empty arrays" {
	const a = t.allocator;
	const line = try renderDeferredJson(a, "p", &.{}, &.{});
	defer a.free(line);
	try t.expectEqualStrings("{\"deferred\":{\"plugin\":\"p\",\"l4\":[],\"l7\":[]}}\n", line);
}
