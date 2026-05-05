const std = @import("std");

pub fn build(b: *std.Build) void {
	const target = b.standardTargetOptions(.{});
	const optimize = b.standardOptimizeOption(.{});

	const filter_mod = b.createModule(.{
		.root_source_file = b.path("src/filter.zig"),
		.target = target,
		.optimize = optimize,
	});

	const lib_mod = b.createModule(.{
		.root_source_file = b.path("src/netfilter/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	lib_mod.addImport("filter", filter_mod);

	const lib = b.addLibrary(.{
		.name = "netfilter",
		.linkage = .dynamic,
		.root_module = lib_mod,
	});
	b.installArtifact(lib);

	const rules_mod = b.createModule(.{
		.root_source_file = b.path("src/rules/main.zig"),
		.target = target,
		.optimize = optimize,
	});
	rules_mod.addImport("filter", filter_mod);

	const rules_exe = b.addExecutable(.{
		.name = "cogbox-rules",
		.root_module = rules_mod,
	});
	b.installArtifact(rules_exe);

	const filter_tests = b.addTest(.{
		.root_module = filter_mod,
	});
	const run_filter_tests = b.addRunArtifact(filter_tests);

	const rules_test_mod = b.createModule(.{
		.root_source_file = b.path("src/rules/tests.zig"),
		.target = target,
		.optimize = optimize,
	});
	rules_test_mod.addImport("filter", filter_mod);
	const rules_tests = b.addTest(.{
		.root_module = rules_test_mod,
	});
	const run_rules_tests = b.addRunArtifact(rules_tests);

	const test_step = b.step("test", "Run unit tests");
	test_step.dependOn(&run_filter_tests.step);
	test_step.dependOn(&run_rules_tests.step);
}
