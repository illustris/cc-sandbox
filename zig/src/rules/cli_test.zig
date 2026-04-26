const std = @import("std");
const cli = @import("cli.zig");

const t = std.testing;

fn argv(comptime items: []const []const u8) []const []const u8 {
	return items;
}

test "list parses with --config and --runtime" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "list" }));
	try t.expectEqualStrings("/c", a.config_path);
	try t.expectEqualStrings("/r", a.runtime_path);
	try t.expect(a.cmd == .list);
}

test "missing --config errors" {
	try t.expectError(error.MissingConfig, cli.parse(argv(&.{ "--runtime", "/r", "list" })));
}

test "missing --runtime errors" {
	try t.expectError(error.MissingRuntime, cli.parse(argv(&.{ "--config", "/c", "list" })));
}

test "missing subcommand errors" {
	try t.expectError(error.MissingSubcommand, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r" })));
}

test "unknown subcommand errors" {
	try t.expectError(error.UnknownSubcommand, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "blast" })));
}

test "add allow without --at" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "10.0.0.0/8" }));
	try t.expect(a.cmd == .add);
	try t.expect(a.cmd.add.action == .allow);
	try t.expectEqualStrings("10.0.0.0/8", a.cmd.add.cidr);
	try t.expect(a.cmd.add.pos == null);
}

test "add deny with --at" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "deny", "10.0.0.0/8", "--at", "3" }));
	try t.expect(a.cmd.add.action == .deny);
	try t.expectEqual(@as(?usize, 3), a.cmd.add.pos);
}

test "add rejects invalid action" {
	try t.expectError(error.InvalidAction, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "block", "10.0.0.0/8" })));
}

test "add rejects --at 0" {
	try t.expectError(error.InvalidIndex, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "10.0.0.0/8", "--at", "0" })));
}

test "del with valid index" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "del", "5" }));
	try t.expect(a.cmd == .del);
	try t.expectEqual(@as(usize, 5), a.cmd.del.index);
}

test "del rejects 0 and missing arg" {
	try t.expectError(error.InvalidIndex, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "del", "0" })));
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "del" })));
}

test "set takes no extra args" {
	const a = try cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "set" }));
	try t.expect(a.cmd == .set);
	try t.expectError(error.InvalidArgs, cli.parse(argv(&.{ "--config", "/c", "--runtime", "/r", "set", "extra" })));
}
