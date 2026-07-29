// Argument parser for `cogbox l7`. Mirrors `cogbox rules` so the operator's
// mental model is identical, with one extra subcommand (`mode`).
//
//   cogbox l7 --config CFG --runtime RT list
//   cogbox l7 --config CFG --runtime RT add allow|deny HOST [--at N]
//        [--path P] [--method M[,M]] [--exact] [--service SVC]
//        [--terminate|--passthrough|--insecure-upstream] [--plugin TAG]
//   cogbox l7 --config CFG --runtime RT del INDEX
//   cogbox l7 --config CFG --runtime RT clear --plugin TAG  (drop all TAG rules)
//   cogbox l7 --config CFG --runtime RT set                 (reads stdin)
//   cogbox l7 --config CFG --runtime RT mode passthrough|terminate

const std = @import("std");
const rule = @import("rule.zig");

pub const Cmd = union(enum) {
	list,
	add: AddArgs,
	del: DelArgs,
	clear: ClearArgs,
	set,
	mode: ModeArgs,
};

pub const AddArgs = struct {
	action: rule.Action,
	host: []const u8,
	pos: ?usize = null, // 1-based; null = append
	path: ?[]const u8 = null, // URL path prefix; implies terminate
	terminate: bool = false, // route this host through the terminate tier
	insecure: bool = false, // skip upstream cert verification; implies terminate
	passthrough: bool = false, // opt OUT of the terminate default (SNI-only)
	// --plugin NAME: tag the inserted rule with `"plugin": "<name>"` so a later
	// `plugin del <name>` / `l7 clear --plugin <name>` removes exactly it
	// (admin-approved deferred plugin rule, or a git-grant-tagged rule).
	plugin: ?[]const u8 = null,
	// --method M[,M]: constrain the rule to an uppercase HTTP method list.
	methods: ?[]const u8 = null,
	// --exact: match the path by full equality instead of the default prefix.
	exact: bool = false,
	// --service SVC: constrain to a git smart-HTTP service (git-upload-pack /
	// git-receive-pack).
	service: ?[]const u8 = null,
};

pub const DelArgs = struct {
	index: usize, // 1-based
};

pub const ClearArgs = struct {
	// Remove every rule tagged with this `"plugin"` value (e.g. `git-grants`).
	plugin: []const u8,
};

pub const ModeArgs = struct {
	terminate: bool,
};

pub const Args = struct {
	config_path: []const u8,
	runtime_path: []const u8,
	cmd: Cmd,
};

pub const ParseError = error{
	MissingConfig,
	MissingRuntime,
	MissingSubcommand,
	UnknownSubcommand,
	InvalidArgs,
	InvalidAction,
	InvalidMode,
	InvalidIndex,
};

pub fn parse(argv: []const []const u8) ParseError!Args {
	var config: ?[]const u8 = null;
	var runtime: ?[]const u8 = null;
	var i: usize = 0;

	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--config")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			config = argv[i];
		} else if (std.mem.eql(u8, a, "--runtime")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			runtime = argv[i];
		} else if (std.mem.startsWith(u8, a, "--")) {
			return error.InvalidArgs;
		} else {
			break;
		}
	}

	const cfg_path = config orelse return error.MissingConfig;
	const rt_path = runtime orelse return error.MissingRuntime;
	if (i >= argv.len) return error.MissingSubcommand;

	const sub = argv[i];
	i += 1;
	const sub_args = argv[i..];

	if (std.mem.eql(u8, sub, "list")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .list };
	}
	if (std.mem.eql(u8, sub, "set")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .set };
	}
	if (std.mem.eql(u8, sub, "add")) return parseAdd(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "del")) return parseDel(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "clear")) return parseClear(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "mode")) return parseMode(cfg_path, rt_path, sub_args);
	return error.UnknownSubcommand;
}

fn parseAdd(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len < 2) return error.InvalidArgs;
	const action = parseAction(args[0]) orelse return error.InvalidAction;
	const host = args[1];
	var pos: ?usize = null;
	var path: ?[]const u8 = null;
	var terminate = false;
	var insecure = false;
	var passthrough = false;
	var plugin: ?[]const u8 = null;
	var methods: ?[]const u8 = null;
	var exact = false;
	var service: ?[]const u8 = null;

	var i: usize = 2;
	while (i < args.len) : (i += 1) {
		if (std.mem.eql(u8, args[i], "--at")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			pos = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidIndex;
			if (pos.? == 0) return error.InvalidIndex;
		} else if (std.mem.eql(u8, args[i], "--path")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			path = args[i];
			if (path.?.len == 0 or path.?[0] != '/') return error.InvalidArgs;
		} else if (std.mem.eql(u8, args[i], "--terminate")) {
			terminate = true;
		} else if (std.mem.eql(u8, args[i], "--insecure-upstream")) {
			insecure = true;
		} else if (std.mem.eql(u8, args[i], "--passthrough")) {
			passthrough = true;
		} else if (std.mem.eql(u8, args[i], "--plugin")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			plugin = args[i];
		} else if (std.mem.eql(u8, args[i], "--method")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			methods = args[i];
			if (!validMethods(methods.?)) return error.InvalidArgs;
		} else if (std.mem.eql(u8, args[i], "--exact")) {
			exact = true;
		} else if (std.mem.eql(u8, args[i], "--service")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			service = args[i];
			if (service.?.len == 0) return error.InvalidArgs;
		} else {
			return error.InvalidArgs;
		}
	}

	// A path constraint is only enforceable on a terminated stream, and
	// skipping upstream cert verification only makes sense when we terminate
	// (it governs the proxy<->upstream TLS leg); both imply terminate. A
	// method/exact/service constraint is likewise only meaningful on the
	// terminated leg, so it implies terminate too.
	if (path != null or insecure or methods != null or exact or service != null) terminate = true;

	// --passthrough is the opt-OUT of the terminate default; it can't be
	// combined with anything that forces (or implies) terminate.
	if (passthrough and (terminate or path != null or insecure or methods != null or exact or service != null)) return error.InvalidArgs;

	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .add = .{ .action = action, .host = host, .pos = pos, .path = path, .terminate = terminate, .insecure = insecure, .passthrough = passthrough, .plugin = plugin, .methods = methods, .exact = exact, .service = service } },
	};
}

/// A `--method` value is a non-empty comma-separated list of uppercase-ASCII
/// method tokens (`GET` / `GET,POST`). Rejects lowercase / empty / stray chars
/// so the rendered l7-rules line's METHODS token round-trips through the zig
/// parser (which admits only all-uppercase-and-comma method tokens).
fn validMethods(s: []const u8) bool {
	if (s.len == 0) return false;
	var saw_letter = false;
	for (s) |c| switch (c) {
		'A'...'Z' => saw_letter = true,
		',' => {},
		else => return false,
	};
	return saw_letter;
}

fn parseClear(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 2 or !std.mem.eql(u8, args[0], "--plugin")) return error.InvalidArgs;
	if (args[1].len == 0) return error.InvalidArgs;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .clear = .{ .plugin = args[1] } },
	};
}

fn parseDel(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	const idx = std.fmt.parseInt(usize, args[0], 10) catch return error.InvalidIndex;
	if (idx == 0) return error.InvalidIndex;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .del = .{ .index = idx } },
	};
}

fn parseMode(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	var terminate: bool = undefined;
	if (std.mem.eql(u8, args[0], "passthrough")) {
		terminate = false;
	} else if (std.mem.eql(u8, args[0], "terminate")) {
		terminate = true;
	} else {
		return error.InvalidMode;
	}
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .mode = .{ .terminate = terminate } },
	};
}

fn parseAction(s: []const u8) ?rule.Action {
	if (std.mem.eql(u8, s, "allow")) return .allow;
	if (std.mem.eql(u8, s, "deny")) return .deny;
	return null;
}

// --- Tests ---

const t = std.testing;

test "list parses" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "list" });
	try t.expect(a.cmd == .list);
}

test "add allow host without --at" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "vhost-a.test" });
	try t.expect(a.cmd == .add);
	try t.expectEqual(rule.Action.allow, a.cmd.add.action);
	try t.expectEqualStrings("vhost-a.test", a.cmd.add.host);
	try t.expect(a.cmd.add.pos == null);
}

test "add with --at" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "deny", "*.evil.test", "--at", "2" });
	try t.expectEqual(@as(?usize, 2), a.cmd.add.pos);
	try t.expectEqual(rule.Action.deny, a.cmd.add.action);
}

test "add rejects bad action and --at 0" {
	try t.expectError(error.InvalidAction, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "permit", "a.test" }));
	try t.expectError(error.InvalidIndex, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--at", "0" }));
}

test "add --path implies terminate" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.test", "--path", "/v1/" });
	try t.expectEqualStrings("/v1/", a.cmd.add.path.?);
	try t.expect(a.cmd.add.terminate);
}

test "add --terminate without path" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.test", "--terminate" });
	try t.expect(a.cmd.add.path == null);
	try t.expect(a.cmd.add.terminate);
}

test "add --insecure-upstream implies terminate" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "internal.svc", "--insecure-upstream" });
	try t.expect(a.cmd.add.insecure);
	try t.expect(a.cmd.add.terminate);
	try t.expect(a.cmd.add.path == null);
}

test "add --insecure-upstream composes with --path" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "internal.svc", "--path", "/api/", "--insecure-upstream" });
	try t.expectEqualStrings("/api/", a.cmd.add.path.?);
	try t.expect(a.cmd.add.insecure);
	try t.expect(a.cmd.add.terminate);
}

test "add rejects malformed --path" {
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--path", "noslash" }));
}

test "add --passthrough opts out, and rejects mixing with terminate flags" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "pinned.test", "--passthrough" });
	try t.expect(a.cmd.add.passthrough);
	try t.expect(!a.cmd.add.terminate);
	// --passthrough can't be combined with anything that forces terminate
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "x.test", "--passthrough", "--terminate" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "x.test", "--passthrough", "--path", "/v1/" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "x.test", "--passthrough", "--insecure-upstream" }));
}

test "add --plugin tag" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com", "--plugin", "obs-plugin" });
	try t.expectEqualStrings("obs-plugin", a.cmd.add.plugin.?);
	try t.expectEqualStrings("api.example.com", a.cmd.add.host);
	// Default is no tag (backward compat).
	const b = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com" });
	try t.expect(b.cmd.add.plugin == null);
	// Combines with --path / --at.
	const c = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com", "--path", "/v1/", "--plugin", "p", "--at", "1" });
	try t.expectEqualStrings("p", c.cmd.add.plugin.?);
	try t.expect(c.cmd.add.terminate);
	// --plugin without a value errors.
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com", "--plugin" }));
}

test "add --method/--exact/--service parse and imply terminate" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "git.example.internal", "--method", "POST", "--exact", "--service", "git-upload-pack", "--path", "/g/p.git/git-upload-pack", "--plugin", "git-grants" });
	try t.expect(a.cmd == .add);
	try t.expectEqualStrings("POST", a.cmd.add.methods.?);
	try t.expect(a.cmd.add.exact);
	try t.expectEqualStrings("git-upload-pack", a.cmd.add.service.?);
	try t.expectEqualStrings("git-grants", a.cmd.add.plugin.?);
	try t.expect(a.cmd.add.terminate); // any of method/exact/service implies terminate
	// A comma method list is accepted.
	const b = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--method", "GET,POST" });
	try t.expectEqualStrings("GET,POST", b.cmd.add.methods.?);
	// Back-compat: no new flags -> all empty/false.
	const c = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test" });
	try t.expect(c.cmd.add.methods == null);
	try t.expect(!c.cmd.add.exact);
	try t.expect(c.cmd.add.service == null);
	// lowercase / empty method values reject; --passthrough can't mix with them.
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--method", "get" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--passthrough", "--exact" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--service" }));
}

test "clear --plugin parses; rejects missing/other flag" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "clear", "--plugin", "git-grants" });
	try t.expect(a.cmd == .clear);
	try t.expectEqualStrings("git-grants", a.cmd.clear.plugin);
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "clear" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "clear", "git-grants" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "clear", "--plugin", "" }));
}

test "mode terminate parses (no longer rejected at parse)" {
	const m = try parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "terminate" });
	try t.expect(m.cmd.mode.terminate);
}

test "del + mode parse" {
	const d = try parse(&.{ "--config", "/c", "--runtime", "/r", "del", "3" });
	try t.expectEqual(@as(usize, 3), d.cmd.del.index);
	const m = try parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "terminate" });
	try t.expect(m.cmd.mode.terminate);
	try t.expectError(error.InvalidMode, parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "sideways" }));
}

test "unknown subcommand" {
	try t.expectError(error.UnknownSubcommand, parse(&.{ "--config", "/c", "--runtime", "/r", "blast" }));
}
