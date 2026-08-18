const std = @import("std");
const units = @import("units.zig");
const t = std.testing;

// --- enumerate: the filters must be the BUILD's filters ---------------------

// A self-made contents root under cwd; the caller owns teardown.
fn tmpRoot(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-units-test-{s}", .{hexb});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

fn writeFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [256]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn has(list: []const units.Unit, kind: units.Kind, name: []const u8) bool {
	for (list) |u| {
		if (u.kind == kind and std.mem.eql(u8, u.name, name)) return true;
	}
	return false;
}

test "enumerate mirrors flake.nix discovery: SKILL.md gate, README excluded, basename is the name" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpRoot(gpa, io);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};

	var arena_state = std.heap.ArenaAllocator.init(gpa);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	const j = std.fs.path.join;
	// A skill is a DIRECTORY carrying SKILL.md...
	try cwd.createDirPath(io, try j(arena, &.{ root, "skills", "overview" }));
	try writeFile(io, try j(arena, &.{ root, "skills", "overview", "SKILL.md" }), "---\nname: overview\n---\n");
	// ...so a directory without one is not a skill, and neither is a stray file.
	try cwd.createDirPath(io, try j(arena, &.{ root, "skills", "notaskill" }));
	try writeFile(io, try j(arena, &.{ root, "skills", "loose.md" }), "x\n");
	// agent/command/rule: <name>.md, README.md excluded, non-.md ignored.
	try cwd.createDirPath(io, try j(arena, &.{ root, "agents" }));
	try writeFile(io, try j(arena, &.{ root, "agents", "triage.md" }), "---\nname: triage\n---\n");
	try writeFile(io, try j(arena, &.{ root, "agents", "README.md" }), "docs\n");
	try writeFile(io, try j(arena, &.{ root, "agents", "notes.txt" }), "x\n");
	try cwd.createDirPath(io, try j(arena, &.{ root, "commands", "nested" }));
	try writeFile(io, try j(arena, &.{ root, "commands", "deploy.md" }), "x\n");
	// contents/rules is simply absent: an absent root yields nothing, never an
	// error (flake.nix readDirSafe).

	const found = try units.enumerate(arena, io, root);
	try t.expect(has(found, .skill, "overview"));
	try t.expect(!has(found, .skill, "notaskill"));
	try t.expect(!has(found, .skill, "loose.md"));
	try t.expect(has(found, .agent, "triage"));
	try t.expect(!has(found, .agent, "README"));
	try t.expect(!has(found, .agent, "notes"));
	try t.expect(has(found, .command, "deploy"));
	try t.expect(!has(found, .command, "nested"));
	try t.expectEqual(@as(usize, 3), found.len);

	// A root that does not exist at all is empty, not an error.
	const none = try units.enumerate(arena, io, try j(arena, &.{ root, "no-such-contents" }));
	try t.expectEqual(@as(usize, 0), none.len);
}

// --- analyze: the resolution the build performs -----------------------------

fn mk(arena: std.mem.Allocator, kind: units.Kind, names: []const []const u8) ![]units.Unit {
	const out = try arena.alloc(units.Unit, names.len);
	for (names, 0..) |n, i| out[i] = .{ .kind = kind, .name = n };
	return out;
}

test "analyze: a name only one plugin provides is left alone" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	const r = try units.analyze(arena, &.{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .skill, &.{"runbook"}) },
	});
	try t.expectEqual(@as(usize, 0), r.collisions.len);
	try t.expectEqual(@as(usize, 0), r.fatals.len);
}

test "analyze: two plugins providing one name collide advisorily, both sides qualified" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	const r = try units.analyze(arena, &.{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
	});
	// ADVISORY, not fatal: the build installs both as <plugin>-overview.
	try t.expectEqual(@as(usize, 0), r.fatals.len);
	try t.expectEqual(@as(usize, 1), r.collisions.len);
	try t.expectEqual(units.Kind.skill, r.collisions[0].kind);
	try t.expectEqualStrings("overview", r.collisions[0].name);
	// Install order, which is the order the composition imports them in.
	try t.expectEqual(@as(usize, 2), r.collisions[0].plugins.len);
	try t.expectEqualStrings("obs-plugin", r.collisions[0].plugins[0]);
	try t.expectEqualStrings("demo-plugin", r.collisions[0].plugins[1]);
	// The final names ride along, index-aligned, so no caller re-derives the
	// qualification rule and drifts from the build.
	try t.expectEqual(@as(usize, 2), r.collisions[0].finals.len);
	try t.expectEqualStrings("obs-plugin-overview", r.collisions[0].finals[0]);
	try t.expectEqualStrings("demo-plugin-overview", r.collisions[0].finals[1]);
}

test "analyze: kinds are separate namespaces" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	// A skill and an agent both called `overview` land in different harness
	// directories, so they are not a collision at all.
	const r = try units.analyze(arena, &.{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .agent, &.{"overview"}) },
	});
	try t.expectEqual(@as(usize, 0), r.collisions.len);
	try t.expectEqual(@as(usize, 0), r.fatals.len);
}

test "analyze: the reserved index name is fatal and names the plugin" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	const r = try units.analyze(arena, &.{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{units.reserved_skill_name}) },
	});
	try t.expectEqual(@as(usize, 1), r.fatals.len);
	// The point of the message is that it names WHO and WHAT; the old failure
	// was a bare `ln: File exists` naming neither.
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "plugin 'obs-plugin'") != null);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "cogbox-plugins") != null);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "cogbox.skills") != null);

	// Reserved for SKILLS only: no other kind has an index leaf.
	const ok = try units.analyze(arena, &.{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .agent, &.{units.reserved_skill_name}) },
	});
	try t.expectEqual(@as(usize, 0), ok.fatals.len);
}

test "analyze: the reserved index name is fatal when reached by QUALIFICATION" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	// Neither plugin ships `cogbox-plugins`. Both ship `plugins`, so both copies
	// are qualified -- and the one installed as `cogbox` lands exactly on the
	// leaf the generated index occupies. Testing only the DISCOVERED name misses
	// this entirely: the two finals are distinct, so the claimed-twice pass sees
	// nothing either, and the brain build then dies on a bare `ln`/`cp` error
	// naming neither plugin nor unit.
	const r = try units.analyze(arena, &.{
		.{ .plugin = "cogbox", .units = try mk(arena, .skill, &.{"plugins"}) },
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"plugins"}) },
	});
	try t.expectEqual(@as(usize, 1), r.fatals.len);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "skill 'plugins'") != null);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "plugin 'cogbox'") != null);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "qualifies to 'cogbox-plugins'") != null);
	// The collision that CAUSED the qualification is still reported as one.
	try t.expectEqual(@as(usize, 1), r.collisions.len);
}

test "analyze: a qualified name that is already taken is fatal" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	// 'obs-plugin' and 'demo-plugin' both ship `overview`, so demo-plugin's copy
	// becomes `demo-plugin-overview` -- which 'docs-plugin' already ships under
	// that literal name. Last-wins here is precisely the failure mode the
	// qualification pass exists to remove, so it must refuse.
	const r = try units.analyze(arena, &.{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
		.{ .plugin = "docs-plugin", .units = try mk(arena, .skill, &.{"demo-plugin-overview"}) },
	});
	try t.expectEqual(@as(usize, 1), r.fatals.len);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "skill name 'demo-plugin-overview' is claimed twice") != null);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "plugin 'docs-plugin' provides 'demo-plugin-overview'") != null);
	try t.expect(std.mem.indexOf(u8, r.fatals[0], "which cogbox qualified to 'demo-plugin-overview'") != null);
	// The advisory for the collision that CAUSED the qualification still stands.
	try t.expectEqual(@as(usize, 1), r.collisions.len);
}

test "delta: a pre-existing fatal does not block an unrelated add" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	// An instance that ALREADY carries an unresolvable name plus a resolved
	// collision. Installing something unrelated must not be refused for it: the
	// add makes nothing worse, refusing it would only strand the operator, and
	// the pre-existing residue still fails the build with the build's message.
	const installed = [_]units.Provider{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{ "overview", units.reserved_skill_name }) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
	};
	const before = try units.analyze(arena, &installed);
	try t.expectEqual(@as(usize, 1), before.fatals.len);
	try t.expectEqual(@as(usize, 1), before.collisions.len);

	const unrelated = installed ++ [_]units.Provider{
		.{ .plugin = "docs-plugin", .units = try mk(arena, .skill, &.{"runbook"}) },
	};
	const d = try units.delta(arena, before, try units.analyze(arena, &unrelated), "docs-plugin");
	try t.expectEqual(@as(usize, 0), d.fatals.len);
	try t.expectEqual(@as(usize, 0), d.collisions.len);

	// ...but a fatal this add CAUSES is reported, even though the message names
	// only the two plugins that were already installed: a third provider of
	// `overview` is what forces demo-plugin's copy to become
	// `demo-plugin-overview`, and obs-plugin already ships that literal name.
	const causes = [_]units.Provider{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"demo-plugin-overview"}) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
	};
	const quiet = try units.analyze(arena, &causes);
	try t.expectEqual(@as(usize, 0), quiet.fatals.len);
	const loud = try units.analyze(arena, &(causes ++ [_]units.Provider{
		.{ .plugin = "docs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
	}));
	const d2 = try units.delta(arena, quiet, loud, "docs-plugin");
	try t.expectEqual(@as(usize, 1), d2.fatals.len);
	try t.expect(std.mem.indexOf(u8, d2.fatals[0], "'demo-plugin-overview' is claimed twice") != null);
}

test "delta: joining an EXISTING collision as a third provider is still reported" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	// The newcomer's own copy is renamed too, and that new name is exactly what
	// the operator installed the plugin to use -- so filtering this collision
	// out as "the instance already had it" would hide the one fact they need.
	const installed = [_]units.Provider{
		.{ .plugin = "obs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
		.{ .plugin = "demo-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
	};
	const before = try units.analyze(arena, &installed);
	const after = try units.analyze(arena, &(installed ++ [_]units.Provider{
		.{ .plugin = "docs-plugin", .units = try mk(arena, .skill, &.{"overview"}) },
	}));
	const d = try units.delta(arena, before, after, "docs-plugin");
	try t.expectEqual(@as(usize, 1), d.collisions.len);
	try t.expectEqual(@as(usize, 3), d.collisions[0].finals.len);
	try t.expectEqualStrings("docs-plugin-overview", d.collisions[0].finals[2]);

	// A collision the newcomer is NOT party to stays quiet: it is not news, and
	// nothing about it changed.
	const elsewhere = installed ++ [_]units.Provider{
		.{ .plugin = "docs-plugin", .units = try mk(arena, .skill, &.{"runbook"}) },
	};
	const d2 = try units.delta(arena, before, try units.analyze(arena, &elsewhere), "docs-plugin");
	try t.expectEqual(@as(usize, 0), d2.collisions.len);
}
