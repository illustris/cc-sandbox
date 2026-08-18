// Add-time unit-name lint: what a plugin's `contents/` tree will contribute to
// the guest brain, and how those names land against the plugins already
// installed.
//
// WHY THIS EXISTS. Nothing on the host has ever looked inside a plugin's
// contents/ -- the add-time evals in nix.zig read only the flake's cheap policy
// outputs (networkRules/l7Rules/inject), never the module -- so the first sign
// that two plugins ship a skill by the same name was a guest system that would
// not EVALUATE: `cogbox init` exiting non-zero, the supervisor restart-looping,
// and the one line of Nix error that explained it reachable only from inside
// the VM. The build now RESOLVES cross-plugin collisions itself (flake.nix
// `resolveKind`: every colliding plugin copy is installed as `<plugin>-<unit>`),
// so this lint is ADVISORY for that case -- it tells the operator, at the moment
// they choose to install, what their units will actually be called -- and FATAL
// for exactly the residue the build still refuses, so the CLI and the build can
// never disagree about what installs.
//
// DELIBERATELY A HEURISTIC on one point: this reads `<source>/contents`, the
// conventional root docs/plugins.md documents, because the CLI does not evaluate
// the plugin module and therefore cannot know what `cogbox.contents` was
// actually set to. A plugin that points it elsewhere is simply not seen here.
// The build remains the authority; this is the early, cheap, attributed warning.

const std = @import("std");

/// The four discovered unit kinds, in the order flake.nix resolves them.
pub const Kind = enum {
	skill,
	agent,
	command,
	rule,

	/// The `contents/` subdirectory this kind is discovered from.
	pub fn dir(k: Kind) []const u8 {
		return switch (k) {
			.skill => "skills",
			.agent => "agents",
			.command => "commands",
			.rule => "rules",
		};
	}

	/// The singular noun the build's collision messages use, and the stem of
	/// the explicit override option (`cogbox.<label>s`). Kept identical to
	/// flake.nix's `kind` strings so the two texts read the same.
	pub fn label(k: Kind) []const u8 {
		return switch (k) {
			.skill => "skill",
			.agent => "agent",
			.command => "command",
			.rule => "rule",
		};
	}
};

const all_kinds = [_]Kind{ .skill, .agent, .command, .rule };

/// The name cogbox reserves for its own generated capability index
/// (flake.nix `reservedSkillName`). SKILLS ONLY: no other kind has an index
/// leaf, so no other kind reserves anything.
pub const reserved_skill_name = "cogbox-plugins";

pub const Unit = struct {
	kind: Kind,
	name: []const u8,
};

/// One contents root, tagged with the plugin that ships it. `plugin` is the
/// INSTALL name -- the same string the composition stamps as `_file = "p-<name>"`
/// and the build qualifies colliding copies with.
pub const Provider = struct {
	plugin: []const u8,
	units: []const Unit,
};

/// A name two or more plugins both provide. The build installs one copy per
/// plugin as `<plugin>-<name>` and none of them keeps the bare name, so this is
/// information, not an error.
pub const Collision = struct {
	kind: Kind,
	name: []const u8,
	/// Every plugin providing `name`, in provider order; len >= 2.
	plugins: []const []const u8,
	/// What each of those copies ends up called, index-aligned with `plugins`.
	/// Carried rather than re-derived by the caller so the qualification rule
	/// lives in exactly one place.
	finals: []const []const u8,
};

pub const Report = struct {
	collisions: []const Collision,
	/// What the composed guest would REFUSE to evaluate. Each entry is a
	/// complete sentence mirroring the corresponding `lib.throwIf` in
	/// flake.nix, minus its `cogbox: ` prefix (the CLI supplies its own).
	fatals: []const []const u8,
};

fn unitLess(_: void, a: Unit, b: Unit) bool {
	if (a.kind != b.kind) return @intFromEnum(a.kind) < @intFromEnum(b.kind);
	return std.mem.lessThan(u8, a.name, b.name);
}

/// Enumerate one contents root exactly the way flake.nix's discoverSkills /
/// discoverMd do: a skill is a SUBDIRECTORY of contents/skills containing
/// SKILL.md; an agent/command/rule is a `<name>.md` FILE under contents/<kind>s
/// with README.md excluded. A unit's name is its basename, never its
/// frontmatter.
///
/// The entry-type tests are `.directory` / `.file` rather than "resolve the
/// symlink" because builtins.readDir reports a symlink as `"symlink"` and the
/// build's own filters therefore skip it too. Matching that here is the whole
/// point: the lint's answer has to be the guest's contents, not an approximation.
///
/// A root that is absent or unreadable yields NO units rather than an error,
/// mirroring flake.nix's readDirSafe. This is a lint; it must never be the
/// reason an add fails.
///
/// Names are dup'd into `allocator` -- pass an arena. The result is sorted by
/// (kind, name) so nothing downstream depends on readdir order.
pub fn enumerate(allocator: std.mem.Allocator, io: std.Io, root: []const u8) ![]Unit {
	var out: std.ArrayList(Unit) = .empty;
	errdefer out.deinit(allocator);
	const cwd = std.Io.Dir.cwd();

	for (all_kinds) |kind| {
		const dir_path = try std.fs.path.join(allocator, &.{ root, kind.dir() });
		var d = cwd.openDir(io, dir_path, .{ .iterate = true }) catch continue;
		defer d.close(io);
		var iter = d.iterate();
		// A mid-iteration read error ends this kind rather than the add.
		while (iter.next(io) catch null) |entry| {
			if (kind == .skill) {
				if (entry.kind != .directory) continue;
				const marker = try std.fs.path.join(allocator, &.{ dir_path, entry.name, "SKILL.md" });
				cwd.access(io, marker, .{}) catch continue;
				try out.append(allocator, .{ .kind = kind, .name = try allocator.dupe(u8, entry.name) });
			} else {
				if (entry.kind != .file) continue;
				if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
				if (std.mem.eql(u8, entry.name, "README.md")) continue;
				const stem = entry.name[0 .. entry.name.len - ".md".len];
				try out.append(allocator, .{ .kind = kind, .name = try allocator.dupe(u8, stem) });
			}
		}
	}

	const slice = try out.toOwnedSlice(allocator);
	std.mem.sort(Unit, slice, {}, unitLess);
	return slice;
}

/// `plugin 'a', plugin 'b'` -- flake.nix's `tagLabel` joined the way its
/// messages join it, so the two texts are recognizably the same message.
fn pluginLabels(arena: std.mem.Allocator, names: []const []const u8) ![]const u8 {
	var buf: std.ArrayList(u8) = .empty;
	for (names, 0..) |n, i| {
		if (i > 0) try buf.appendSlice(arena, ", ");
		try buf.appendSlice(arena, "plugin '");
		try buf.appendSlice(arena, n);
		try buf.appendSlice(arena, "'");
	}
	return buf.toOwnedSlice(arena);
}

/// Resolve the discovered names across `providers` the way the build does, and
/// report what the operator needs to know: the names that will be qualified,
/// and the names that cannot be resolved at all.
///
/// This mirrors flake.nix `resolveKind` minus the two root classes the CLI
/// cannot see: the instance's own flake (which keeps the bare name when it is
/// one of the colliders) and an unattributed root. Both only ever make the
/// build's answer MORE permissive toward plugin copies than this one, never
/// less, so the lint cannot bless something the build then refuses on those
/// grounds. What it can do is miss a residue involving a root it cannot see;
/// that residue still fails the build, with the build's own message.
///
/// Everything is allocated in `arena`, and the returned strings borrow the
/// plugin/unit names from `providers`.
pub fn analyze(arena: std.mem.Allocator, providers: []const Provider) !Report {
	// One row per (kind, name, provider), sorted so equal names form a
	// contiguous run and providers inside a run stay in install order.
	const Occ = struct { kind: Kind, name: []const u8, pi: usize };
	var occs: std.ArrayList(Occ) = .empty;
	for (providers, 0..) |p, pi| {
		for (p.units) |u| try occs.append(arena, .{ .kind = u.kind, .name = u.name, .pi = pi });
	}
	std.mem.sort(Occ, occs.items, {}, struct {
		fn less(_: void, a: Occ, b: Occ) bool {
			if (a.kind != b.kind) return @intFromEnum(a.kind) < @intFromEnum(b.kind);
			const ord = std.mem.order(u8, a.name, b.name);
			if (ord != .eq) return ord == .lt;
			return a.pi < b.pi;
		}
	}.less);

	// What each unit ends up CALLED, which is what the second pass groups on.
	const Final = struct {
		kind: Kind,
		final: []const u8,
		orig: []const u8,
		plugin: []const u8,
		qualified: bool,
	};
	var finals: std.ArrayList(Final) = .empty;
	var collisions: std.ArrayList(Collision) = .empty;
	var fatals: std.ArrayList([]const u8) = .empty;

	var i: usize = 0;
	while (i < occs.items.len) {
		var j = i + 1;
		while (j < occs.items.len and occs.items[j].kind == occs.items[i].kind and
			std.mem.eql(u8, occs.items[j].name, occs.items[i].name)) : (j += 1)
		{}
		const run = occs.items[i..j];
		i = j;

		const kind = run[0].kind;
		const name = run[0].name;

		const plugs = try arena.alloc([]const u8, run.len);
		for (run, 0..) |o, k| plugs[k] = providers[o.pi].plugin;

		// The generated capability index is linked in at
		// claude/skills/cogbox-plugins, so a plugin shipping a skill by that
		// name has nowhere to go -- with or without a second provider. Left
		// unchecked this used to surface as a bare `ln: File exists` naming
		// nobody.
		if (kind == .skill and std.mem.eql(u8, name, reserved_skill_name)) {
			try fatals.append(arena, try std.fmt.allocPrint(
				arena,
				"{s} '{s}' (from {s}) uses the name cogbox reserves for its own generated capability index. Rename that {s} in the plugin, or place it under a different name with cogbox.{s}s.",
				.{ kind.label(), name, try pluginLabels(arena, plugs), kind.label(), kind.label() },
			));
			continue;
		}

		// The overwhelmingly common case: one provider, name unchanged.
		if (run.len == 1) {
			try finals.append(arena, .{
				.kind = kind,
				.final = name,
				.orig = name,
				.plugin = plugs[0],
				.qualified = false,
			});
			continue;
		}

		// Two or more plugins: every copy is renamed, none keeps the bare name.
		const quals = try arena.alloc([]const u8, run.len);
		for (0..run.len) |k| {
			quals[k] = try std.fmt.allocPrint(arena, "{s}-{s}", .{ plugs[k], name });
			try finals.append(arena, .{
				.kind = kind,
				.final = quals[k],
				.orig = name,
				.plugin = plugs[k],
				.qualified = true,
			});
		}
		try collisions.append(arena, .{ .kind = kind, .name = name, .plugins = plugs, .finals = quals });
	}

	// A qualified `<plugin>-<unit>` can land on a name that is already taken --
	// plugin 'a' shipping a skill literally called `b-overview` while plugins
	// 'b' and 'c' both ship `overview`. Silently last-wins here would
	// reintroduce exactly the failure mode the qualification pass removes, so
	// the build refuses it and so does this.
	std.mem.sort(Final, finals.items, {}, struct {
		fn less(_: void, a: Final, b: Final) bool {
			if (a.kind != b.kind) return @intFromEnum(a.kind) < @intFromEnum(b.kind);
			var ord = std.mem.order(u8, a.final, b.final);
			if (ord != .eq) return ord == .lt;
			ord = std.mem.order(u8, a.orig, b.orig);
			if (ord != .eq) return ord == .lt;
			return std.mem.lessThan(u8, a.plugin, b.plugin);
		}
	}.less);

	i = 0;
	while (i < finals.items.len) {
		var j = i + 1;
		while (j < finals.items.len and finals.items[j].kind == finals.items[i].kind and
			std.mem.eql(u8, finals.items[j].final, finals.items[i].final)) : (j += 1)
		{}
		const run = finals.items[i..j];
		i = j;

		// The reserved index name is reachable by QUALIFICATION too, which the
		// discovered-name test above cannot see: a plugin installed as `cogbox`
		// shipping `skills/plugins` becomes `cogbox-plugins` the moment a second
		// plugin also ships `plugins`. Both finals are then unique, so the
		// claimed-twice test below never fires. flake.nix refuses this in its own
		// finals pass; refuse it here too, or the CLI blesses an add whose next
		// boot cannot evaluate the guest.
		if (run[0].kind == .skill and std.mem.eql(u8, run[0].final, reserved_skill_name)) {
			const plugs = try arena.alloc([]const u8, run.len);
			for (run, 0..) |e, k| plugs[k] = e.plugin;
			try fatals.append(arena, try std.fmt.allocPrint(
				arena,
				"skill '{s}' (from {s}) qualifies to '{s}', which is the name cogbox reserves for its own generated capability index. Rename that skill in the plugin, or place it under a different name with cogbox.skills.",
				.{ run[0].orig, try pluginLabels(arena, plugs), reserved_skill_name },
			));
			continue;
		}

		if (run.len < 2) continue;

		var clauses: std.ArrayList(u8) = .empty;
		for (run, 0..) |e, k| {
			if (k > 0) try clauses.appendSlice(arena, "; ");
			if (e.qualified) {
				try clauses.appendSlice(arena, try std.fmt.allocPrint(
					arena,
					"plugin '{s}' provides '{s}', which cogbox qualified to '{s}' because '{s}' collides across plugins",
					.{ e.plugin, e.orig, e.final, e.orig },
				));
			} else {
				try clauses.appendSlice(arena, try std.fmt.allocPrint(
					arena,
					"plugin '{s}' provides '{s}'",
					.{ e.plugin, e.final },
				));
			}
		}
		try fatals.append(arena, try std.fmt.allocPrint(
			arena,
			"{s} name '{s}' is claimed twice: {s}. The qualified name is unavailable, so rename the {s} in one of them or set cogbox.{s}s explicitly.",
			.{ run[0].kind.label(), run[0].final, clauses.items, run[0].kind.label(), run[0].kind.label() },
		));
	}

	return .{ .collisions = try collisions.toOwnedSlice(arena), .fatals = try fatals.toOwnedSlice(arena) };
}

/// Narrow a full `after` report down to what installing `added` is responsible
/// for. The two halves are filtered differently, and the asymmetry is the point:
///
///   - COLLISIONS are kept when `added` is one of the providers, INCLUDING a
///     collision the instance already had. Joining an existing pair as a third
///     provider still renames the newcomer's copy, and that new name is exactly
///     what the operator installed the plugin to use.
///   - FATALS are kept only when `before` did not already have them. An
///     instance already carrying an unresolvable pair is not made worse by
///     installing something unrelated, and refusing that unrelated add would
///     only strand the operator; the pre-existing residue still fails the build,
///     with the build's own message. A before/after diff (rather than a
///     names-`added` test) is required here because a fatal can be CAUSED by the
///     new plugin without naming it -- a third provider of `overview` forces
///     plugin 'b' to qualify to `b-overview`, which a fourth plugin may already
///     have claimed.
pub fn delta(arena: std.mem.Allocator, before: Report, after: Report, added: []const u8) !Report {
	var collisions: std.ArrayList(Collision) = .empty;
	for (after.collisions) |c| {
		for (c.plugins) |p| {
			if (std.mem.eql(u8, p, added)) {
				try collisions.append(arena, c);
				break;
			}
		}
	}
	var fatals: std.ArrayList([]const u8) = .empty;
	next: for (after.fatals) |f| {
		for (before.fatals) |b| {
			if (std.mem.eql(u8, b, f)) continue :next;
		}
		try fatals.append(arena, f);
	}
	return .{ .collisions = try collisions.toOwnedSlice(arena), .fatals = try fatals.toOwnedSlice(arena) };
}
