// Shared argv parser used by every cogbox verb.
//
// Supports:
//   --key value
//   --key=value
//   short forms (-n, -h, -y) declared per-verb
//   `--` terminator: everything after is positional/forwarded
//
// Each verb constructs a Spec describing its accepted flags and parses
// argv with `parse(spec, argv) -> Parsed`. Unknown flags exit with
// EX_USAGE; missing values (`--name --foo`) exit with EX_USAGE too.

const std = @import("std");
const util = @import("util.zig");
const exit_codes = @import("exit.zig");

pub const FlagKind = enum {
	/// `--flag` (no value)
	bool,
	/// `--flag VALUE` or `--flag=VALUE`
	value,
	/// `--flag VALUE`, REPEATABLE: every occurrence is retained in argv order
	/// (`getAll`). `get`/`isSet` still see the last one, so a caller that does
	/// not care about repetition behaves exactly like `.value`.
	value_multi,
};

pub const Flag = struct {
	long: []const u8, // without leading "--"
	short: ?u8 = null,
	kind: FlagKind,
};

pub const Spec = struct {
	verb: []const u8, // for error messages, e.g. "run"
	flags: []const Flag,
	/// If true, accept positional args (preserved in `Parsed.positional`).
	allow_positional: bool = false,
	/// If true, accept `--` as a terminator and put everything after into
	/// `Parsed.trailing` verbatim. Used by `ssh` to forward remote command.
	allow_trailing: bool = false,
	/// If true, stop flag parsing at the first positional arg and forward
	/// everything after (including flag-shaped tokens) to `Parsed.trailing`.
	/// Useful for verbs that proxy commands, like ssh.
	terminate_on_positional: bool = false,
};

/// One occurrence of a `.value_multi` flag.
pub const MultiValue = struct {
	name: []const u8, // flag long-name
	value: []const u8,
};

pub const Parsed = struct {
	/// Map from flag long-name to the parsed value. For bool flags the
	/// value is "" (presence == set). Unset flags are absent.
	values: std.StringHashMap([]const u8),
	/// Every occurrence of every `.value_multi` flag, in argv order. A map
	/// cannot hold these: it keeps one value per key by construction.
	multi: std.ArrayList(MultiValue),
	positional: std.ArrayList([]const u8),
	trailing: std.ArrayList([]const u8),
	allocator: std.mem.Allocator,

	pub fn deinit(self: *Parsed) void {
		self.values.deinit();
		self.multi.deinit(self.allocator);
		self.positional.deinit(self.allocator);
		self.trailing.deinit(self.allocator);
	}

	pub fn isSet(self: *const Parsed, name: []const u8) bool {
		return self.values.contains(name);
	}

	pub fn get(self: *const Parsed, name: []const u8) ?[]const u8 {
		return self.values.get(name);
	}

	/// Every value given for a repeatable flag, in argv order. Empty when the
	/// flag was never given. Caller owns the returned slice; the values inside
	/// it are borrowed from argv, like every other `Parsed` accessor.
	pub fn getAll(self: *const Parsed, allocator: std.mem.Allocator, name: []const u8) ![]const []const u8 {
		var out: std.ArrayList([]const u8) = .empty;
		errdefer out.deinit(allocator);
		for (self.multi.items) |m| {
			if (std.mem.eql(u8, m.name, name)) try out.append(allocator, m.value);
		}
		return try out.toOwnedSlice(allocator);
	}
};

pub fn parse(
	allocator: std.mem.Allocator,
	io: std.Io,
	spec: Spec,
	argv: []const []const u8,
) Parsed {
	var values = std.StringHashMap([]const u8).init(allocator);
	var multi: std.ArrayList(MultiValue) = .empty;
	var positional: std.ArrayList([]const u8) = .empty;
	var trailing: std.ArrayList([]const u8) = .empty;

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];

		if (spec.allow_trailing and std.mem.eql(u8, a, "--")) {
			i += 1;
			while (i < argv.len) : (i += 1) {
				trailing.append(allocator, argv[i]) catch oom();
			}
			break;
		}

		if (std.mem.startsWith(u8, a, "--")) {
			const rest = a[2..];
			// --key=value
			if (std.mem.indexOfScalar(u8, rest, '=')) |eq| {
				const name = rest[0..eq];
				const val = rest[eq + 1 ..];
				const flag = findLong(spec.flags, name) orelse {
					util.die(allocator, io, spec.verb, exit_codes.usage, "unknown flag --{s}", .{name});
				};
				if (flag.kind == .bool) {
					util.die(allocator, io, spec.verb, exit_codes.usage, "--{s} does not take a value", .{name});
				}
				values.put(flag.long, val) catch oom();
				if (flag.kind == .value_multi) {
					multi.append(allocator, .{ .name = flag.long, .value = val }) catch oom();
				}
				continue;
			}
			// --key [value]
			const flag = findLong(spec.flags, rest) orelse {
				util.die(allocator, io, spec.verb, exit_codes.usage, "unknown flag --{s}", .{rest});
			};
			if (flag.kind == .bool) {
				values.put(flag.long, "") catch oom();
				continue;
			}
			i += 1;
			if (i >= argv.len or looksLikeFlag(argv[i])) {
				util.die(allocator, io, spec.verb, exit_codes.usage, "--{s} requires a value", .{rest});
			}
			values.put(flag.long, argv[i]) catch oom();
			if (flag.kind == .value_multi) {
				multi.append(allocator, .{ .name = flag.long, .value = argv[i] }) catch oom();
			}
			continue;
		}

		// short flag(s): -n VALUE, -h. Multi-char short bundles (-vh) not
		// supported -- not worth the complexity for our small flag set.
		if (a.len >= 2 and a[0] == '-' and a[1] != '-') {
			if (a.len > 2) {
				util.die(allocator, io, spec.verb, exit_codes.usage, "unknown flag {s} (short flags do not bundle)", .{a});
			}
			const c = a[1];
			const flag = findShort(spec.flags, c) orelse {
				util.die(allocator, io, spec.verb, exit_codes.usage, "unknown flag -{c}", .{c});
			};
			if (flag.kind == .bool) {
				values.put(flag.long, "") catch oom();
				continue;
			}
			i += 1;
			if (i >= argv.len or looksLikeFlag(argv[i])) {
				util.die(allocator, io, spec.verb, exit_codes.usage, "-{c} requires a value", .{c});
			}
			values.put(flag.long, argv[i]) catch oom();
			if (flag.kind == .value_multi) {
				multi.append(allocator, .{ .name = flag.long, .value = argv[i] }) catch oom();
			}
			continue;
		}

		// positional
		if (spec.terminate_on_positional) {
			trailing.append(allocator, a) catch oom();
			i += 1;
			while (i < argv.len) : (i += 1) {
				trailing.append(allocator, argv[i]) catch oom();
			}
			break;
		}
		if (!spec.allow_positional) {
			util.die(allocator, io, spec.verb, exit_codes.usage, "unexpected argument: {s}", .{a});
		}
		positional.append(allocator, a) catch oom();
	}

	return .{
		.values = values,
		.multi = multi,
		.positional = positional,
		.trailing = trailing,
		.allocator = allocator,
	};
}

fn findLong(flags: []const Flag, name: []const u8) ?*const Flag {
	for (flags) |*f| {
		if (std.mem.eql(u8, f.long, name)) return f;
	}
	return null;
}

fn findShort(flags: []const Flag, c: u8) ?*const Flag {
	for (flags) |*f| {
		if (f.short) |s| if (s == c) return f;
	}
	return null;
}

fn looksLikeFlag(s: []const u8) bool {
	// A bare "--" terminator is not a flag. A bare "-" (e.g. stdin
	// shortcut) is also not a flag here. Otherwise, leading dash means
	// flag-shaped and must not be consumed as a value.
	if (std.mem.eql(u8, s, "--") or std.mem.eql(u8, s, "-")) return false;
	return s.len > 0 and s[0] == '-';
}

fn oom() noreturn {
	@panic("out of memory in argv parser");
}

// ---------- validators -------------------------------------------------

pub const ValidationError = error{
	NotInteger,
	OutOfRange,
	InvalidName,
	InvalidNetworkMode,
};

pub fn parseIntRange(s: []const u8, min: u32, max: u32) !u32 {
	const n = std.fmt.parseInt(u32, s, 10) catch return error.NotInteger;
	if (n < min or n > max) return error.OutOfRange;
	return n;
}

pub const NetworkMode = enum { full, none, rules };

pub fn parseNetworkMode(s: []const u8) !NetworkMode {
	if (std.mem.eql(u8, s, "full")) return .full;
	if (std.mem.eql(u8, s, "none")) return .none;
	if (std.mem.eql(u8, s, "rules")) return .rules;
	return error.InvalidNetworkMode;
}

/// Instance name validator: `^[a-zA-Z][a-zA-Z0-9-]{0,63}$`. Mirrors the
/// regex enforced by the previous bash entrypoint.
pub fn isValidName(s: []const u8) bool {
	if (s.len == 0 or s.len > 64) return false;
	const c0 = s[0];
	if (!std.ascii.isAlphabetic(c0)) return false;
	for (s[1..]) |c| {
		if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
	}
	return true;
}

// ---------- tests ------------------------------------------------------

test "parseIntRange accepts in-range" {
	const v = try parseIntRange("8", 1, 256);
	try std.testing.expectEqual(@as(u32, 8), v);
}

test "parseIntRange rejects non-numeric" {
	try std.testing.expectError(error.NotInteger, parseIntRange("abc", 1, 256));
}

test "parseIntRange rejects out-of-range" {
	try std.testing.expectError(error.OutOfRange, parseIntRange("0", 1, 256));
	try std.testing.expectError(error.OutOfRange, parseIntRange("999", 1, 256));
}

test "parseNetworkMode accepts the three modes" {
	try std.testing.expectEqual(NetworkMode.full, try parseNetworkMode("full"));
	try std.testing.expectEqual(NetworkMode.none, try parseNetworkMode("none"));
	try std.testing.expectEqual(NetworkMode.rules, try parseNetworkMode("rules"));
}

test "parseNetworkMode rejects others" {
	try std.testing.expectError(error.InvalidNetworkMode, parseNetworkMode("Full"));
	try std.testing.expectError(error.InvalidNetworkMode, parseNetworkMode(""));
}

test "isValidName" {
	try std.testing.expect(isValidName("work"));
	try std.testing.expect(isValidName("a"));
	try std.testing.expect(isValidName("a-b-c"));
	try std.testing.expect(!isValidName(""));
	try std.testing.expect(!isValidName("1abc"));
	try std.testing.expect(!isValidName("-abc"));
	try std.testing.expect(!isValidName("a_b"));
	try std.testing.expect(!isValidName("a b"));
}

// `.value_multi` serves security-sensitive repeatable inputs. Keeping the
// original mixed-flag order matters for launch-time directory grants, while
// retaining every self-address prevents silently shrinking the L7 floor.
test "value_multi retains every occurrence in argv order" {
	const flags = [_]Flag{
		.{ .long = "self-addr", .kind = .value_multi },
		.{ .long = "name", .short = 'n', .kind = .value },
	};
	var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
	defer threaded.deinit();
	var p = parse(std.testing.allocator, threaded.io(), .{ .verb = "init", .flags = &flags }, &.{
		"--self-addr", "10.0.0.1/32",
		"--name",      "demo",
		"--self-addr=10.0.0.2/32",
	});
	defer p.deinit();

	const all = try p.getAll(std.testing.allocator, "self-addr");
	defer std.testing.allocator.free(all);
	try std.testing.expectEqual(@as(usize, 2), all.len);
	try std.testing.expectEqualStrings("10.0.0.1/32", all[0]);
	try std.testing.expectEqualStrings("10.0.0.2/32", all[1]);
	// The single-value accessors keep working (last occurrence wins).
	try std.testing.expect(p.isSet("self-addr"));
	try std.testing.expectEqualStrings("10.0.0.2/32", p.get("self-addr").?);
	try std.testing.expectEqualStrings("demo", p.get("name").?);
}

test "getAll returns empty for an unset or non-multi flag" {
	const flags = [_]Flag{
		.{ .long = "self-addr", .kind = .value_multi },
		.{ .long = "name", .kind = .value },
	};
	var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
	defer threaded.deinit();
	var p = parse(std.testing.allocator, threaded.io(), .{ .verb = "init", .flags = &flags }, &.{ "--name", "demo" });
	defer p.deinit();

	const none = try p.getAll(std.testing.allocator, "self-addr");
	defer std.testing.allocator.free(none);
	try std.testing.expectEqual(@as(usize, 0), none.len);
	// A `.value` flag never lands in the repeat list, however often it appears.
	const not_multi = try p.getAll(std.testing.allocator, "name");
	defer std.testing.allocator.free(not_multi);
	try std.testing.expectEqual(@as(usize, 0), not_multi.len);
}

test "looksLikeFlag" {
	try std.testing.expect(looksLikeFlag("--foo"));
	try std.testing.expect(looksLikeFlag("-n"));
	try std.testing.expect(!looksLikeFlag("--"));
	try std.testing.expect(!looksLikeFlag("-"));
	try std.testing.expect(!looksLikeFlag("foo"));
	try std.testing.expect(!looksLikeFlag(""));
}
