// Round-trip tests for the jq --tab compatible serializer. The seed string
// here is the exact byte sequence produced by `jq -n --tab '...'` for a
// representative cc-sandbox config -- matching it byte-for-byte means a
// no-op edit produces no diff against existing user files.

const std = @import("std");
const config = @import("config.zig");

const t = std.testing;

const seed_json =
	"{\n" ++
	"\t\"vcpu\": 16,\n" ++
	"\t\"network\": {\n" ++
	"\t\t\"rules\": [\n" ++
	"\t\t\t{\n" ++
	"\t\t\t\t\"deny\": \"10.0.0.0/8\",\n" ++
	"\t\t\t\t\"comment\": \"RFC1918 private\"\n" ++
	"\t\t\t},\n" ++
	"\t\t\t{\n" ++
	"\t\t\t\t\"allow\": \"0.0.0.0/0\",\n" ++
	"\t\t\t\t\"comment\": \"public internet\"\n" ++
	"\t\t\t}\n" ++
	"\t\t]\n" ++
	"\t}\n" ++
	"}\n";

test "writeJqTab matches jq --tab byte-for-byte on a representative config" {
	const allocator = t.allocator;

	const parsed = try std.json.parseFromSlice(std.json.Value, allocator, seed_json, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try config.writeJqTab(allocator, &out, parsed.value);

	try t.expectEqualStrings(seed_json, out.items);
}

test "empty arrays and objects render inline" {
	const allocator = t.allocator;

	const src = "{\n\t\"a\": [],\n\t\"b\": {}\n}\n";
	const parsed = try std.json.parseFromSlice(std.json.Value, allocator, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try config.writeJqTab(allocator, &out, parsed.value);

	try t.expectEqualStrings(src, out.items);
}

test "string escapes are written correctly" {
	const allocator = t.allocator;

	const src = "{\n\t\"k\": \"a\\tb\\\"c\\\\d\"\n}\n";
	const parsed = try std.json.parseFromSlice(std.json.Value, allocator, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try config.writeJqTab(allocator, &out, parsed.value);

	try t.expectEqualStrings(src, out.items);
}
