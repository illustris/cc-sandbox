const std = @import("std");
const rule = @import("rule.zig");

const t = std.testing;

test "parseSetLine valid allow" {
	const p = (try rule.parseSetLine("allow 10.0.0.0/8")).?;
	try t.expect(p.action == .allow);
	try t.expectEqualStrings("10.0.0.0/8", p.cidr);
}

test "parseSetLine valid deny with leading whitespace" {
	const p = (try rule.parseSetLine("\tdeny 192.168.0.0/16")).?;
	try t.expect(p.action == .deny);
	try t.expectEqualStrings("192.168.0.0/16", p.cidr);
}

test "parseSetLine empty and comment lines return null" {
	try t.expect((try rule.parseSetLine("")) == null);
	try t.expect((try rule.parseSetLine("   ")) == null);
	try t.expect((try rule.parseSetLine("# whatever")) == null);
}

test "parseSetLine rejects unknown action" {
	try t.expectError(error.InvalidLine, rule.parseSetLine("block 10.0.0.0/8"));
}

test "parseSetLine rejects malformed CIDR" {
	try t.expectError(error.InvalidLine, rule.parseSetLine("allow garbage"));
	try t.expectError(error.InvalidLine, rule.parseSetLine("allow 10.0.0.0"));
	try t.expectError(error.InvalidLine, rule.parseSetLine("allow 10.0.0.0/33"));
}

test "validateActionCidr accepts good CIDR, rejects bad" {
	var buf: [128]u8 = undefined;
	try t.expect(rule.validateActionCidr(.allow, "10.0.0.0/8", &buf));
	try t.expect(!rule.validateActionCidr(.allow, "garbage", &buf));
	try t.expect(!rule.validateActionCidr(.deny, "10.0.0.0/33", &buf));
}

test "newRuleObject builds the right shape" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const v = try rule.newRuleObject(arena.allocator(), .deny, "192.168.0.0/16");
	try t.expect(v == .object);
	const got = v.object.get("deny") orelse return error.TestUnexpectedNull;
	try t.expect(got == .string);
	try t.expectEqualStrings("192.168.0.0/16", got.string);
}

test "ruleAction reads back action+cidr from obj" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const v = try rule.newRuleObject(arena.allocator(), .allow, "8.8.8.8/32");
	const p = rule.ruleAction(v.object).?;
	try t.expect(p.action == .allow);
	try t.expectEqualStrings("8.8.8.8/32", p.cidr);
}

test "ruleComment returns null when missing" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const v = try rule.newRuleObject(arena.allocator(), .allow, "1.1.1.1/32");
	try t.expect(rule.ruleComment(v.object) == null);
}
