// Aggregator file pulling unit tests from every module.
// Run via `zig build test`.

const std = @import("std");

test {
	std.testing.refAllDecls(@import("cli.zig"));
	std.testing.refAllDecls(@import("rule.zig"));
	std.testing.refAllDecls(@import("config.zig"));
	_ = @import("cli_test.zig");
	_ = @import("rule_test.zig");
	_ = @import("config_test.zig");
}
