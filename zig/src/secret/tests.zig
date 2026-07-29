// Unit tests for the secret store's PURE layer (validName + meta
// serialize/parse). The IO layer (add/lookup/remove on disk) is covered by the
// launcher + NixOS VM integration tests, mirroring how rules/config_test.zig
// leaves load/save IO to integration coverage. refAllDecls forces the verb
// dispatch code (main.zig) to type-check here too.

const std = @import("std");
const store = @import("store.zig");
const main = @import("main.zig");
const t = std.testing;

test {
	std.testing.refAllDecls(main);
	std.testing.refAllDecls(store);
}

test "validName accepts valid names, rejects traversal/charset/length" {
	try t.expect(store.validName("api-bearer"));
	try t.expect(store.validName("app_session"));
	try t.expect(store.validName("a"));
	try t.expect(store.validName("A0-_z"));
	try t.expect(!store.validName(""));
	try t.expect(!store.validName("has.dot")); // '.' excluded so <name>.meta is unambiguous
	try t.expect(!store.validName("has/slash"));
	try t.expect(!store.validName(".."));
	try t.expect(!store.validName("../etc/passwd"));
	try t.expect(!store.validName("with space"));
	try t.expect(!store.validName("x" ** 65)); // > 64 chars
}

test "validKind allowlist accepts the injection styles incl. anthropic-oauth" {
	try t.expect(main.validKind("bearer"));
	try t.expect(main.validKind("cookie"));
	try t.expect(main.validKind("basic"));
	// The per-user Claude setup-token bind without
	// this the `claude-oauth` bind FAILS CLOSED at `secret add`.
	try t.expect(main.validKind("anthropic-oauth"));
	try t.expectEqualStrings("anthropic-oauth", main.anthropic_oauth_kind);
	// The per-user GitLab (git OAuth) access-token bind; without this the
	// `git-<provider>` bind FAILS CLOSED at `secret add`.
	try t.expect(main.validKind("gitlab-oauth"));
	try t.expectEqualStrings("gitlab-oauth", main.gitlab_oauth_kind);
	try t.expectEqualStrings("oauth2", main.default_git_user);
	// unknown styles are still rejected (fail closed)
	try t.expect(!main.validKind("oauth"));
	try t.expect(!main.validKind("anthropic"));
	try t.expect(!main.validKind("gitlab"));
	try t.expect(!main.validKind(""));
}

test "stubCredentialJson stages ONLY the shared sentinel, never a real token" {
	const a = t.allocator;
	const json = try main.stubCredentialJson(a);
	defer a.free(json);
	// The accessToken is the single shared stub sentinel (the addon stamps the real
	// Bearer over exactly this -- the real token never enters the agent).
	try t.expect(std.mem.indexOf(u8, json, main.claude_stub_token) != null);
	try t.expect(std.mem.indexOf(u8, json, "\"accessToken\":\"" ++ main.claude_stub_token ++ "\"") != null);
	// The refresh token is the in-guest eviction sentinel, never a usable one, and a
	// far-future expiry stops the guest from refreshing the placeholder locally.
	try t.expect(std.mem.indexOf(u8, json, "cogbox-evicted-no-refresh-token-in-guest") != null);
	try t.expect(std.mem.indexOf(u8, json, "9999999999000") != null);
	// Read-only scopes keep a logged-in identity without inference-write power.
	try t.expect(std.mem.indexOf(u8, json, "user:inference") != null);
	// It parses as the credential shape claude-code reads.
	var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
	defer parsed.deinit();
	const at = parsed.value.object.get("claudeAiOauth").?.object.get("accessToken").?.string;
	try t.expectEqualStrings(main.claude_stub_token, at);
}

test "buildMeta/parseMeta round-trip" {
	const a = t.allocator;
	const m: store.Meta = .{ .audience = "api.example.com", .kind = "bearer", .tier = "durable", .bound_at = 1234 };
	const json = try store.buildMeta(a, m);
	defer a.free(json);

	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), json);
	try t.expectEqualStrings("api.example.com", parsed.audience.?);
	try t.expectEqualStrings("bearer", parsed.kind);
	try t.expectEqualStrings("durable", parsed.tier);
	try t.expectEqual(@as(i64, 1234), parsed.bound_at.?);
}

test "parseMeta handles null audience and missing fields with defaults" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), "{\"audience\": null, \"kind\": \"cookie\"}");
	try t.expect(parsed.audience == null);
	try t.expectEqualStrings("cookie", parsed.kind);
	try t.expectEqualStrings("durable", parsed.tier); // default kept
	try t.expect(parsed.bound_at == null);
}

test "parseMeta tolerates malformed json -> defaults (fail safe)" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), "not json{");
	try t.expect(parsed.audience == null);
	try t.expectEqualStrings("bearer", parsed.kind);
}

test "buildMeta emits null audience/bound_at literally" {
	const a = t.allocator;
	const m: store.Meta = .{ .audience = null, .kind = "cookie", .tier = "derived", .bound_at = null };
	const json = try store.buildMeta(a, m);
	defer a.free(json);
	try t.expect(std.mem.indexOf(u8, json, "\"audience\": null") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"kind\": \"cookie\"") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"tier\": \"derived\"") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"bound_at\": null") != null);
}

// `secret ls --json` shape the control plane (cogworx) parses. A bound secret
// carries its audience + bound_at; an unset audience / missing value render as
// JSON null / bound:false so cogworx shows the inject request as not injectable.
test "appendSecretJson emits bound and unbound shapes" {
	const a = t.allocator;
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "api-token", .{ .audience = "api.example.com", .kind = "bearer", .tier = "durable", .bound_at = 1700000000 }, true);
		try t.expectEqualStrings(
			"{\"name\":\"api-token\",\"kind\":\"bearer\",\"audience\":\"api.example.com\",\"tier\":\"durable\",\"bound\":true,\"bound_at\":1700000000}",
			out.items,
		);
	}
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "app-session", .{ .audience = null, .kind = "cookie", .tier = "durable", .bound_at = null }, false);
		try t.expectEqualStrings(
			"{\"name\":\"app-session\",\"kind\":\"cookie\",\"audience\":null,\"tier\":\"durable\",\"bound\":false,\"bound_at\":null}",
			out.items,
		);
	}
}
