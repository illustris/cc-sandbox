const std = @import("std");

pub fn build(b: *std.Build) void {
	const target = b.standardTargetOptions(.{});
	const optimize = b.standardOptimizeOption(.{});

	const lib_mod = b.createModule(.{
		.root_source_file = b.path("src/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});

	const lib = b.addLibrary(.{
		.name = "netfilter",
		.linkage = .dynamic,
		.root_module = lib_mod,
	});
	b.installArtifact(lib);

	const test_mod = b.createModule(.{
		.root_source_file = b.path("src/filter.zig"),
		.target = target,
		.optimize = optimize,
	});

	const filter_tests = b.addTest(.{
		.root_module = test_mod,
	});
	const run_tests = b.addRunArtifact(filter_tests);
	const test_step = b.step("test", "Run unit tests");
	test_step.dependOn(&run_tests.step);
}
