// `cogbox enforce -n <name>` - the container enforcer sidecar's entrypoint
// (PID1 of the enforcer container).
//
// There is no VM here: this verb only resolves the instance name, then execs
// the bash supervisor (libexec/cogbox-enforce.sh) in place. The supervisor
// writes the nft cgroup handshake, renders the wire files (`cogbox
// __render-rules`), and runs mitmdump + `cogbox __l7proxy` in nft-REDIRECT
// accept mode (COGBOX_L7_ACCEPT=redirect). It reads XDG_CONFIG_HOME /
// COGBOX_DIVERT_PORT / the secret-dir overrides straight from the container
// env, so this verb passes only the instance name through.
//
// Not a user-facing verb (the pod's `command:` runs it); it is in the hidden
// helper group of KNOWN_VERBS alongside __l7proxy / __render-rules.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const exit_codes = @import("../exit.zig");
const launch = @import("../launch.zig");

const USAGE =
	\\cogbox enforce - run the container enforcer supervisor (sidecar PID1)
	\\
	\\Usage:
	\\  cogbox enforce [-n NAME]
	\\
	\\Resolves the instance (the -n flag, else $COGBOX_INSTANCE, else "default")
	\\and execs libexec/cogbox-enforce.sh, which renders the wire rules and runs
	\\mitmdump + the L7 proxy in nft-REDIRECT accept mode. Intended to be the
	\\enforcer container's entrypoint, not invoked interactively.
	\\
;

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	argv: []const []const u8,
) !void {
	var name: ?[]const u8 = null;

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
			try util.writeStdout(io, USAGE);
			return;
		}
		if (std.mem.eql(u8, a, "--name") or std.mem.eql(u8, a, "-n")) {
			i += 1;
			if (i >= argv.len) util.die(allocator, io, "enforce", exit_codes.usage, "{s} requires a value", .{a});
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
		util.die(allocator, io, "enforce", exit_codes.usage, "unexpected argument '{s}'", .{a});
	}

	// Name precedence: -n flag, else COGBOX_INSTANCE (the pod sets it), else the
	// default instance. The supervisor resolves config.json off this.
	const eff = name orelse env.get("COGBOX_INSTANCE") orelse "default";
	if (!std.mem.eql(u8, eff, "default") and !parse.isValidName(eff)) {
		util.die(allocator, io, "enforce", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
	}

	const script = try launch.resolveEnforceScriptPath(allocator, io, env);
	defer allocator.free(script);

	// Exec the supervisor in place (it becomes PID1). Pass the resolved name as
	// the sole positional arg; cogbox-enforce.sh also honors $COGBOX_INSTANCE.
	const args = [_][]const u8{ script, eff };
	try launch.execvAlloc(allocator, &args);
}
