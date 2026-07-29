const std = @import("std");
const name = @import("name.zig");
const t = std.testing;

fn expectName(expected: []const u8, url: []const u8) !void {
	const got = try name.deriveName(t.allocator, url);
	defer t.allocator.free(got);
	try t.expectEqualStrings(expected, got);
}

test "github refs use the repo segment" {
	try expectName("repo", "github:owner/repo");
	try expectName("repo", "github:owner/repo/main");
	try expectName("repo", "github:owner/repo/0123abcd0123abcd0123abcd0123abcd0123abcd");
}

test "?dir= wins over the repo name" {
	try expectName("flake", "github:owner/repo?dir=flake");
	try expectName("flake", "git+https://example.com/x/repo.git?ref=main&dir=sub/flake");
}

test "git+https strips host and .git" {
	try expectName("repo", "git+https://git.example.com/group/repo.git");
	try expectName("repo", "git+ssh://git@github.com/owner/repo.git?ref=main");
}

test "path flakes use the basename" {
	try expectName("myplugin", "path:/home/me/src/myplugin");
	try expectName("myplugin", "path:/home/me/src/myplugin/");
	try expectName("plugin", "/abs/dir/plugin");
}

test "sanitization maps _ and . to dashes and trims" {
	try expectName("my-plugin-x", "path:/x/my_plugin.x");
	try expectName("abc", "path:/x/123abc"); // leading digits dropped
	try expectName("abc", "path:/x/abc---"); // trailing dashes trimmed
}

test "underivable urls error" {
	try t.expectError(error.CannotDerive, name.deriveName(t.allocator, "path:/x/1234"));
	try t.expectError(error.CannotDerive, name.deriveName(t.allocator, "github:owneronly"));
	try t.expectError(error.CannotDerive, name.deriveName(t.allocator, "path:/x/user")); // reserved
	try t.expectError(error.CannotDerive, name.deriveName(t.allocator, "path:/x/git-grants")); // reserved (backend L7 tag)
}

test "splitFragment" {
	const plain = try name.splitFragment("github:o/r?dir=flake");
	try t.expectEqualStrings("github:o/r?dir=flake", plain.ref);
	try t.expect(plain.attr == null);

	const frag = try name.splitFragment("github:o/r#extra-mod");
	try t.expectEqualStrings("github:o/r", frag.ref);
	try t.expectEqualStrings("extra-mod", frag.attr.?);

	const under = try name.splitFragment("path:/x/y#my_mod");
	try t.expectEqualStrings("my_mod", under.attr.?);

	try t.expectError(error.EmptyFragment, name.splitFragment("github:o/r#"));
	try t.expectError(error.InvalidAttr, name.splitFragment("github:o/r#a.b"));
	try t.expectError(error.InvalidAttr, name.splitFragment("github:o/r#a\"b"));
	try t.expectError(error.InvalidAttr, name.splitFragment("github:o/r#a b"));
}

test "deriveNameFromAttr sanitizes" {
	const got = try name.deriveNameFromAttr(t.allocator, "my_extra");
	defer t.allocator.free(got);
	try t.expectEqualStrings("my-extra", got);
	try t.expectError(error.CannotDerive, name.deriveNameFromAttr(t.allocator, "user"));
	try t.expectError(error.CannotDerive, name.deriveNameFromAttr(t.allocator, "123"));
}

test "validator grammar" {
	try t.expect(name.isValidPluginName("myplugin"));
	try t.expect(name.isValidPluginName("a-b-c"));
	try t.expect(!name.isValidPluginName(""));
	try t.expect(!name.isValidPluginName("1abc"));
	try t.expect(!name.isValidPluginName("a_b"));
	try t.expect(!name.isValidPluginName("user")); // reserved composition input
	try t.expect(!name.isValidPluginName("git-grants")); // reserved backend L7 injection-gating tag
}
