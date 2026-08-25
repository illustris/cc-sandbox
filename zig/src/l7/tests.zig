const std = @import("std");

test {
	std.testing.refAllDecls(@import("cli.zig"));
	std.testing.refAllDecls(@import("rule.zig"));
	std.testing.refAllDecls(@import("main.zig"));
}
