// Shelling out to nix for the plugin verb. Everything network-touching or
// store-touching goes through here: resolving a flake URL to a locked rev
// (metadata), checking the module contract (eval), reading the optional
// cogboxPlugins.<attr> host-side policy output (eval), and pre-fetching the plugin's
// transitive inputs for offline restarts (archive).
//
// Experimental features are passed explicitly (the launcher does the same at
// cogbox-launch.sh's re-exec) so the verb works regardless of user nix.conf.

const std = @import("std");

pub const RunOut = struct {
	stdout: []u8,
	stderr: []u8,
	ok: bool,

	pub fn deinit(self: *RunOut, allocator: std.mem.Allocator) void {
		allocator.free(self.stdout);
		allocator.free(self.stderr);
	}
};

/// Run a `nix` subcommand. `env`, when non-null, REPLACES the child
/// environment for this one invocation -- the plugin fetch passes a per-fetch
/// map (a clone of the parent env with HOME / GIT_CONFIG_* / GIT_TERMINAL_PROMPT
/// overridden) so a private-repo clone authenticates from a temp netrc scoped to
/// exactly this exec. Null inherits the parent env
/// unchanged -- the default for every non-authenticated nix call.
pub fn runNix(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, args: []const []const u8) !RunOut {
	var argv: std.ArrayList([]const u8) = .empty;
	defer argv.deinit(allocator);
	try argv.appendSlice(allocator, &.{ "nix", "--extra-experimental-features", "nix-command flakes" });
	try argv.appendSlice(allocator, args);

	const res = try std.process.run(allocator, io, .{ .argv = argv.items, .environ_map = env });
	const ok = res.term == .exited and res.term.exited == 0;
	return .{ .stdout = res.stdout, .stderr = res.stderr, .ok = ok };
}

/// `refresh` adds `--refresh`, which bypasses nix's flake/tarball eval cache so
/// a mutable ref (e.g. `github:owner/repo` with no rev) re-resolves to the
/// current tip instead of a stale cached rev. `update` sets it; `add`/`resolve`
/// don't (a first resolve has nothing cached to go stale).
pub fn flakeMetadata(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, refresh: bool) !RunOut {
	if (refresh) return runNix(allocator, io, env, &.{ "flake", "metadata", "--refresh", "--json", url });
	return runNix(allocator, io, env, &.{ "flake", "metadata", "--json", url });
}

pub fn flakeArchive(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "flake", "archive", "--json", url });
}

/// `nix flake archive --to <dest> --json <url>`: copy the flake AND its
/// transitive inputs into the `dest` binary cache (a `file://<dir>` URI). The
/// launcher points `--extra-substituters` at that cache so a fresh-store
/// launch substitutes the plugin's tarball/narHash inputs offline (only git+
/// inputs can't substitute -- those are handled by the path: rewrite). Best-
/// effort: a launch with network still rebuilds from the inputs.
pub fn flakeArchiveTo(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, dest: []const u8, url: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "flake", "archive", "--to", dest, "--json", url });
}

/// `nix flake lock <url>`: reconcile the composition flake's lock against its
/// current inputs, writing/updating flake.lock in place. Run after every
/// regen so launch resolves from a coherent lock (path: inputs are read from
/// disk; no fetch). Authenticated (the rewritten inputs are local path: refs,
/// but a migration-fallback git+ input still needs the acting user's token).
pub fn flakeLock(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "flake", "lock", url });
}

/// Inputs for buildRunner. `flake_source`/`nixpkgs_source` are the cogbox
/// flake + nixpkgs store paths (COGBOX_FLAKE_SOURCE / COGBOX_NIXPKGS_SOURCE,
/// baked by mkCogbox); `plugins_flake_dir` is the composition; `arch` is the
/// config-name suffix (x86_64 / aarch64). The substituter knobs combine the
/// per-instance file:// cache with cogworx's remote runner cache so transitive
/// deps substitute rather than build. Empty optional knobs are simply omitted.
pub const RunnerBuild = struct {
	flake_source: []const u8,
	nixpkgs_source: []const u8,
	plugins_flake_dir: []const u8,
	arch: []const u8,
	// "file://<cache_dir> <COGBOX_EXTRA_SUBSTITUTERS>", already joined by the
	// caller (either piece may be empty; the whole string is omitted if empty).
	substituters: []const u8,
	trusted_public_keys: []const u8, // COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS ("" => skip)
	netrc_file: []const u8, // COGBOX_NETRC_FILE ("" => skip)
};

/// Build the `nix build` argv for the runner (everything after `nix
/// --extra-experimental-features ...`, which runNix prepends). Separated from
/// buildRunner so the load-bearing invariant -- that the installable + the
/// --override-input set EXACTLY match cogbox-launch.sh's re-exec, which is what
/// makes the worker-built out-path byte-identical to the one boot looks for --
/// is unit-testable. The returned slice and every interpolated string it owns
/// are freed by argvDeinit. Optional substituter/key/netrc knobs are appended
/// only when non-empty (so an unconfigured worker emits no extra options).
fn runnerBuildArgv(allocator: std.mem.Allocator, b: RunnerBuild) !std.ArrayList([]const u8) {
	return buildArgvFor(allocator, b, "config.microvm.declaredRunner");
}

/// The container backend's counterpart: build `config.system.build.cogboxBrain`
/// with the SAME --override-input set the container boot uses (flake.nix
/// brainResolveContainer), so the pre-built out-path is byte-identical to the one
/// boot evaluates. Pre-copying that closure into the per-instance file:// cache
/// (copyClosureTo) turns the container's egress-less boot rebuild into a local
/// substitution. Same RunnerBuild fields; only the installable leaf differs.
fn brainBuildArgv(allocator: std.mem.Allocator, b: RunnerBuild) !std.ArrayList([]const u8) {
	return buildArgvFor(allocator, b, "config.system.build.cogboxBrain");
}

/// Shared `nix build` argv builder. `installable_attr` is the leaf attribute
/// under `nixosConfigurations.cogbox-<arch>` (the VM runner vs the container
/// brain). The interpolated installable/inputs land at argv indices 1/4/7, which
/// argvDeinit frees; the literal flags are static.
fn buildArgvFor(allocator: std.mem.Allocator, b: RunnerBuild, installable_attr: []const u8) !std.ArrayList([]const u8) {
	const installable = try std.fmt.allocPrint(allocator, "path:{s}#nixosConfigurations.cogbox-{s}.{s}", .{ b.flake_source, b.arch, installable_attr });
	errdefer allocator.free(installable);
	const plugins_input = try std.fmt.allocPrint(allocator, "path:{s}", .{b.plugins_flake_dir});
	errdefer allocator.free(plugins_input);
	const nixpkgs_input = try std.fmt.allocPrint(allocator, "path:{s}", .{b.nixpkgs_source});
	errdefer allocator.free(nixpkgs_input);

	var argv: std.ArrayList([]const u8) = .empty;
	errdefer argv.deinit(allocator);
	try argv.appendSlice(allocator, &.{
		"build",
		installable,
		"--override-input",
		"userExtensions",
		plugins_input,
		"--override-input",
		"userExtensions/user/nixpkgs",
		nixpkgs_input,
		"--no-link",
		"--print-out-paths",
	});
	if (b.substituters.len > 0) {
		try argv.appendSlice(allocator, &.{ "--option", "extra-substituters", b.substituters, "--option", "require-sigs", "false" });
	}
	if (b.trusted_public_keys.len > 0) {
		try argv.appendSlice(allocator, &.{ "--option", "extra-trusted-public-keys", b.trusted_public_keys });
	}
	if (b.netrc_file.len > 0) {
		try argv.appendSlice(allocator, &.{ "--option", "netrc-file", b.netrc_file });
	}
	return argv;
}

/// Free the three interpolated installable/input strings runnerBuildArgv owns
/// (the path:... installable at index 1 and the two path: inputs at 4 and 7),
/// then the list itself. The literal flags are static and must not be freed.
fn argvDeinit(allocator: std.mem.Allocator, argv: *std.ArrayList([]const u8)) void {
	allocator.free(argv.items[1]);
	allocator.free(argv.items[4]);
	allocator.free(argv.items[7]);
	argv.deinit(allocator);
}

/// Build the microvm runner the boot path would build -- the SAME flake ref +
/// the SAME --override-input set as cogbox-launch.sh's re-exec -- so the
/// resulting out-path is byte-identical to the one boot looks for, then return
/// it (`--print-out-paths`, `--no-link`). The worker pod pushes this closure to
/// a binary cache so boot substitutes it instead of rebuilding from source.
/// Determinism: nothing instance-specific is baked into the closure (hostname,
/// ports, keys are launch-time sed rewrites on the OUTPUT), so every worker for
/// the same (cogbox-rev, plugin-set) builds the identical path.
pub fn buildRunner(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, b: RunnerBuild) !RunOut {
	var argv = try runnerBuildArgv(allocator, b);
	defer argvDeinit(allocator, &argv);
	return runNix(allocator, io, env, argv.items);
}

/// Build the container's per-instance cogbox-brain (the same out-path boot
/// evaluates). Realizes cfg.packages' closure via the passed substituters so a
/// later copyClosureTo can seed the offline plugin-cache. Container backend only.
pub fn buildBrain(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, b: RunnerBuild) !RunOut {
	var argv = try brainBuildArgv(allocator, b);
	defer argvDeinit(allocator, &argv);
	return runNix(allocator, io, env, argv.items);
}

/// `nix copy --to <dest> <store_path>`: copy a realized store path AND its
/// runtime closure into the `dest` binary cache (a `file://<dir>` URI). Used to
/// seed the per-instance plugin-cache with the pre-built cogbox-brain closure so
/// the container's egress-less boot substitutes it (require-sigs false on the
/// read side) instead of rebuilding. Unlike flakeArchiveTo (which archives a
/// flake + its source inputs), this copies a BUILT output, unreachable from the
/// composition flake.
pub fn copyClosureTo(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, dest: []const u8, store_path: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "copy", "--to", dest, store_path });
}

/// Outcome of the cogboxPlugins.<attr> contract check. `missing` is the
/// contract violation ("this flake is not a cogbox plugin"); `failed` is
/// everything else that can go wrong with the eval (fetch error, eval error
/// inside the flake) and carries nix's stderr (caller owns it). Conflating
/// the two would misreport any broken URL as a missing plugin.
pub const ModuleCheck = union(enum) {
	present,
	missing,
	failed: []u8,
};

/// `nix eval URL#cogboxPlugins --apply 'm: m ? "<attr>"' --json`. The plugin
/// contract is the cogboxPlugins.<attr> REGISTRATION (which carries the
/// optional `module` reference plus host-side networkRules/l7Rules/inject); a
/// flake without it is not a cogbox plugin. `attr` must satisfy
/// name.isValidAttr (it is interpolated into a nix expression).
pub fn evalHasCogboxPlugin(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, attr: []const u8) !ModuleCheck {
	const installable = try std.fmt.allocPrint(allocator, "{s}#cogboxPlugins", .{url});
	defer allocator.free(installable);
	const apply = try std.fmt.allocPrint(allocator, "m: m ? \"{s}\"", .{attr});
	defer allocator.free(apply);
	var out = try runNix(allocator, io, env, &.{ "eval", installable, "--apply", apply, "--json" });
	defer out.deinit(allocator);
	return switch (classifyModuleCheck(out.ok, out.stdout, out.stderr)) {
		.present => .present,
		.missing => .missing,
		.failed => .{ .failed = try allocator.dupe(u8, out.stderr) },
	};
}

/// Pure classification of the eval result: a clean "true" is present, a clean
/// "false" or a "flake does not provide attribute ... 'cogboxPlugins'" error is
/// missing, any other failure is real and must be surfaced. The missing-attr
/// match is deliberately narrower than stderrSaysMissingAttribute: it requires
/// nix's flake-output phrase naming 'cogboxPlugins', so a plugin flake whose
/// own eval error happens to contain "has no attribute" cannot smuggle a real
/// failure back into the misleading contract message.
pub fn classifyModuleCheck(ok: bool, stdout: []const u8, stderr: []const u8) std.meta.Tag(ModuleCheck) {
	if (ok) {
		const is_true = std.mem.eql(u8, std.mem.trim(u8, stdout, " \t\r\n"), "true");
		return if (is_true) .present else .missing;
	}
	const no_output = std.mem.indexOf(u8, stderr, "does not provide attribute") != null and
		std.mem.indexOf(u8, stderr, "'cogboxPlugins'") != null;
	return if (no_output) .missing else .failed;
}

/// `nix eval URL#cogboxPlugins."<attr>".<leaf> --json` (or the flat path
/// `cogboxPlugins.<leaf>` when `attr` is null). `leaf` is `networkRules`
/// (L4 CIDR rules), `l7Rules` (vhost rules), or `inject` (cred specs). IFD is
/// blocked: reading the host-side policy must never trigger a build of
/// untrusted code at add time. `attr` must satisfy name.isValidAttr; `leaf` is
/// always caller-controlled. (The kit -- cogbox.* in the module -- is NOT read
/// here; it rides the module import at build, not the cheap add-time eval.)
pub fn evalPluginRules(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, attr: ?[]const u8, leaf: []const u8) !RunOut {
	const installable = if (attr) |a|
		try std.fmt.allocPrint(allocator, "{s}#cogboxPlugins.\"{s}\".{s}", .{ url, a, leaf })
	else
		try std.fmt.allocPrint(allocator, "{s}#cogboxPlugins.{s}", .{ url, leaf });
	defer allocator.free(installable);
	return runNix(allocator, io, env, &.{ "eval", installable, "--json", "--no-allow-import-from-derivation" });
}

/// Whether a failed eval's stderr means "that attribute just isn't there"
/// (fine: the output is optional) as opposed to a real evaluation error.
pub fn stderrSaysMissingAttribute(stderr: []const u8) bool {
	return std.mem.indexOf(u8, stderr, "does not provide attribute") != null or
		std.mem.indexOf(u8, stderr, "has no attribute") != null or
		std.mem.indexOf(u8, stderr, "missing attribute") != null;
}

pub const Meta = struct {
	locked_url: []const u8,
	rev: ?[]const u8,
	nar_hash: []const u8,
	// The locked flake's source store path (`.path` of `nix flake metadata
	// --json`): the read-only /nix/store/... directory holding the plugin's
	// source. Empty ("") when the metadata didn't carry it (older nix) or when
	// the Meta was built WITHOUT a metadata call (the sibling-reuse path in
	// cmdAdd) -- callers that need it fall back to `flakeSourcePath`. It backs
	// the path: rewrite that makes launch resolve offline.
	source_path: []const u8,

	pub fn deinit(self: *Meta, allocator: std.mem.Allocator) void {
		allocator.free(self.locked_url);
		if (self.rev) |r| allocator.free(r);
		allocator.free(self.nar_hash);
		allocator.free(self.source_path);
	}
};

pub const MetaError = error{
	BadMetadata,
	OutOfMemory,
};

/// Whether nix's git or hg fetcher serves this locked URL. Covers the
/// `git+`/`hg+` transport spellings and the bare legacy `git://` protocol
/// (which nix accepts and locks WITHOUT a `git+` prefix). These fetchers
/// pass unrecognized query params through to the remote.
pub fn isGitOrHgUrl(url: []const u8) bool {
	return std.mem.startsWith(u8, url, "git+") or
		std.mem.startsWith(u8, url, "hg+") or
		std.mem.startsWith(u8, url, "git://");
}

/// Extract the `dir` query-param value from a flake URL (the subdir the flake
/// lives in, e.g. `?dir=flake`), or null if absent/empty. Only the `?...`
/// query is scanned, so a literal `dir=` in the path can't false-match.
/// Returns a slice into `url`. `nix flake metadata`'s `.path` is the repo ROOT
/// for a `?dir=` flake (the flake.nix is at <path>/<dir>), so a path: rewrite
/// of the materialized source must carry the same `?dir=` to find the flake.
pub fn dirParam(url: []const u8) ?[]const u8 {
	const q = std.mem.indexOfScalar(u8, url, '?') orelse return null;
	var it = std.mem.splitScalar(u8, url[q + 1 ..], '&');
	while (it.next()) |param| {
		if (std.mem.startsWith(u8, param, "dir=")) {
			const v = param["dir=".len..];
			return if (v.len == 0) null else v;
		}
	}
	return null;
}

/// Parse `nix flake metadata --json` output. `.url` is nix's locked URL.
/// For github:/path:/tarball refs that don't already carry a narHash query
/// param, `.locked.narHash` is appended (percent-encoded) so the URL alone
/// pins the content and resolves from the local store offline. git/hg refs
/// never get the param (their fetchers would hand it to the remote); they
/// are pinned by rev alone and resolve offline via the fetcher cache.
pub fn parseMetadata(allocator: std.mem.Allocator, json_text: []const u8) MetaError!Meta {
	const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch {
		return error.BadMetadata;
	};
	defer parsed.deinit();

	const root = parsed.value;
	if (root != .object) return error.BadMetadata;
	const url_v = root.object.get("url") orelse return error.BadMetadata;
	if (url_v != .string) return error.BadMetadata;
	const locked_v = root.object.get("locked") orelse return error.BadMetadata;
	if (locked_v != .object) return error.BadMetadata;
	const nar_v = locked_v.object.get("narHash") orelse return error.BadMetadata;
	if (nar_v != .string) return error.BadMetadata;

	var rev: ?[]const u8 = null;
	errdefer if (rev) |r| allocator.free(r);
	if (locked_v.object.get("rev")) |rv| {
		if (rv == .string) rev = try allocator.dupe(u8, rv.string);
	}

	const nar_hash = try allocator.dupe(u8, nar_v.string);
	errdefer allocator.free(nar_hash);

	// `.path` is the locked flake's source store path; absent on older nix,
	// so default to "" (callers fall back to flakeSourcePath).
	const source_path = blk: {
		if (root.object.get("path")) |pv| {
			if (pv == .string) break :blk try allocator.dupe(u8, pv.string);
		}
		break :blk try allocator.dupe(u8, "");
	};
	errdefer allocator.free(source_path);

	const locked_url = blk: {
		if (std.mem.indexOf(u8, url_v.string, "narHash=") != null) {
			break :blk try allocator.dupe(u8, url_v.string);
		}
		// git/hg locked URLs must NOT grow a narHash param: nix's git and hg
		// fetchers consume only their own query params (ref, rev, shallow,
		// ...) and pass everything else through to the remote, so the forge
		// would be asked for a repo literally named "...?narHash=..." and
		// refuse. The rev pins those URLs (clean trees; the caller warns on
		// rev-less dirty-tree locks); offline starts come from the fetcher
		// cache that `nix flake archive` populates.
		if (isGitOrHgUrl(url_v.string)) {
			break :blk try allocator.dupe(u8, url_v.string);
		}
		const sep: u8 = if (std.mem.indexOfScalar(u8, url_v.string, '?') != null) '&' else '?';
		var buf: std.ArrayList(u8) = .empty;
		defer buf.deinit(allocator);
		try buf.appendSlice(allocator, url_v.string);
		try buf.append(allocator, sep);
		try buf.appendSlice(allocator, "narHash=");
		try appendPercentEncoded(allocator, &buf, nar_v.string);
		break :blk try buf.toOwnedSlice(allocator);
	};

	return .{ .locked_url = locked_url, .rev = rev, .nar_hash = nar_hash, .source_path = source_path };
}

/// Resolve a flake URL to its source store path (`.path` of `nix flake
/// metadata --json`), for callers that hold a URL whose Meta lacked a
/// source_path (the sibling-reuse path in cmdAdd builds Meta WITHOUT a
/// metadata call). Returns an allocated path the caller frees, or "" when nix
/// fails or the field is absent (best-effort; the composition then falls back
/// to the git URL). Authenticated via `env` like every other fetch.
pub fn flakeSourcePath(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8) ![]u8 {
	var out = try flakeMetadata(allocator, io, env, url, false);
	defer out.deinit(allocator);
	if (!out.ok) return try allocator.dupe(u8, "");

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, out.stdout, .{}) catch {
		return try allocator.dupe(u8, "");
	};
	defer parsed.deinit();
	if (parsed.value != .object) return try allocator.dupe(u8, "");
	if (parsed.value.object.get("path")) |pv| {
		if (pv == .string) return try allocator.dupe(u8, pv.string);
	}
	return try allocator.dupe(u8, "");
}

/// Percent-encode a query param value (narHash carries `+`, `/`, `=`).
fn appendPercentEncoded(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	for (s) |c| {
		const safe = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
		if (safe) {
			try out.append(allocator, c);
		} else {
			var hex: [3]u8 = undefined;
			_ = std.fmt.bufPrint(&hex, "%{X:0>2}", .{c}) catch unreachable;
			try out.appendSlice(allocator, &hex);
		}
	}
}

/// The trailing lines of nix's stderr, for error messages. Drops the
/// progress noise but keeps the actual failure.
pub fn stderrTail(stderr: []const u8) []const u8 {
	const trimmed = std.mem.trim(u8, stderr, " \t\r\n");
	const max = 600;
	if (trimmed.len <= max) return trimmed;
	const cut = trimmed[trimmed.len - max ..];
	// Start at the next line boundary so we don't emit half a line.
	if (std.mem.indexOfScalar(u8, cut, '\n')) |i| return cut[i + 1 ..];
	return cut;
}

// --- Tests (private runnerBuildArgv is in scope here) ---

const t = std.testing;

/// Per-element string comparison: expectEqualSlices compares pointers for a
/// []const u8 element, so it can't check argv content. This checks length then
/// each string's bytes.
fn expectArgv(expected: []const []const u8, actual: []const []const u8) !void {
	try t.expectEqual(expected.len, actual.len);
	for (expected, actual) |e, a| try t.expectEqualStrings(e, a);
}

// The load-bearing invariant: the runner build invocation must use the SAME
// installable + the SAME --override-input set as cogbox-launch.sh's re-exec, so
// the worker-built out-path is byte-identical to the one boot substitutes. With
// no substituter/key/netrc knobs set, NO extra --option args are emitted.
test "runnerBuildArgv: matches the boot-path flake ref + override-inputs, no knobs" {
	var argv = try runnerBuildArgv(t.allocator, .{
		.flake_source = "/nix/store/abc-cogbox-source",
		.nixpkgs_source = "/nix/store/def-nixpkgs",
		.plugins_flake_dir = "/var/lib/cogbox/inst/plugins-flake",
		.arch = "x86_64",
		.substituters = "",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"build",
		"path:/nix/store/abc-cogbox-source#nixosConfigurations.cogbox-x86_64.config.microvm.declaredRunner",
		"--override-input",
		"userExtensions",
		"path:/var/lib/cogbox/inst/plugins-flake",
		"--override-input",
		"userExtensions/user/nixpkgs",
		"path:/nix/store/def-nixpkgs",
		"--no-link",
		"--print-out-paths",
	}, argv.items);
}

// The arch suffix flows straight into the config name (cogbox-aarch64), and
// every configured knob appends its --option in order: extra-substituters (with
// require-sigs false), extra-trusted-public-keys, then netrc-file.
test "runnerBuildArgv: aarch64 config name + all substituter knobs appended" {
	var argv = try runnerBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "aarch64",
		.substituters = "file:///cache https://cache.example.com",
		.trusted_public_keys = "cache.example.com-1:KEY=",
		.netrc_file = "/run/secrets/netrc",
	});
	defer argvDeinit(t.allocator, &argv);

	try t.expectEqualStrings("path:/src#nixosConfigurations.cogbox-aarch64.config.microvm.declaredRunner", argv.items[1]);
	try expectArgv(&.{
		"--option", "extra-substituters",       "file:///cache https://cache.example.com",
		"--option", "require-sigs",              "false",
		"--option", "extra-trusted-public-keys", "cache.example.com-1:KEY=",
		"--option", "netrc-file",                "/run/secrets/netrc",
	}, argv.items[10..]);
}

// A configured substituter but no keys/netrc emits exactly the substituter
// option pair -- no stray trusted-keys or netrc options.
test "runnerBuildArgv: substituters only, no keys/netrc" {
	var argv = try runnerBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "x86_64",
		.substituters = "file:///cache",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"--option", "extra-substituters", "file:///cache", "--option", "require-sigs", "false",
	}, argv.items[10..]);
}

// The container brain build must be byte-identical to the runner build EXCEPT
// the installable leaf (config.system.build.cogboxBrain vs the microvm runner):
// the pre-built out-path only substitutes at boot if the installable +
// --override-input set exactly match flake.nix's brainResolveContainer. Lock both.
test "brainBuildArgv: cogboxBrain installable + boot-path override-inputs" {
	var argv = try brainBuildArgv(t.allocator, .{
		.flake_source = "/nix/store/abc-cogbox-source",
		.nixpkgs_source = "/nix/store/def-nixpkgs",
		.plugins_flake_dir = "/var/lib/cogbox/inst/plugins-flake",
		.arch = "x86_64",
		.substituters = "",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"build",
		"path:/nix/store/abc-cogbox-source#nixosConfigurations.cogbox-x86_64.config.system.build.cogboxBrain",
		"--override-input",
		"userExtensions",
		"path:/var/lib/cogbox/inst/plugins-flake",
		"--override-input",
		"userExtensions/user/nixpkgs",
		"path:/nix/store/def-nixpkgs",
		"--no-link",
		"--print-out-paths",
	}, argv.items);
}

// The brain build takes the same substituter/key/netrc knobs as the runner (the
// container seeds file://<cache> so the plugin-tool closure substitutes rather
// than builds from source at add time).
test "brainBuildArgv: aarch64 config name + substituter knobs appended" {
	var argv = try brainBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "aarch64",
		.substituters = "file:///cache https://cache.example.com",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try t.expectEqualStrings("path:/src#nixosConfigurations.cogbox-aarch64.config.system.build.cogboxBrain", argv.items[1]);
	try expectArgv(&.{
		"--option", "extra-substituters", "file:///cache https://cache.example.com", "--option", "require-sigs", "false",
	}, argv.items[10..]);
}
