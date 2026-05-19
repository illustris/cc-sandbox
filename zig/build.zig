const std = @import("std");

pub fn build(b: *std.Build) void {
	const target = b.standardTargetOptions(.{});
	const optimize = b.standardOptimizeOption(.{});

	const filter_mod = b.createModule(.{
		.root_source_file = b.path("src/filter.zig"),
		.target = target,
		.optimize = optimize,
	});

	const socks5_mod = b.createModule(.{
		.root_source_file = b.path("src/socks5/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	socks5_mod.addImport("filter", filter_mod);

	const lib_mod = b.createModule(.{
		.root_source_file = b.path("src/netfilter/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	lib_mod.addImport("filter", filter_mod);
	lib_mod.addImport("socks5", socks5_mod);

	const lib = b.addLibrary(.{
		.name = "netfilter",
		.linkage = .dynamic,
		.root_module = lib_mod,
	});
	b.installArtifact(lib);

	// Rules module: previously the standalone cogbox-rules binary; now
	// imported by the unified cogbox CLI as the `rules` verb.
	const rules_mod = b.createModule(.{
		.root_source_file = b.path("src/rules/main.zig"),
		.target = target,
		.optimize = optimize,
	});
	rules_mod.addImport("filter", filter_mod);

	// Top-level cogbox CLI.
	const cli_mod = b.createModule(.{
		.root_source_file = b.path("src/cli/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	cli_mod.addImport("rules_module", rules_mod);
	cli_mod.addImport("filter", filter_mod);

	const cogbox_exe = b.addExecutable(.{
		.name = "cogbox",
		.root_module = cli_mod,
	});
	b.installArtifact(cogbox_exe);

	const filter_tests = b.addTest(.{
		.root_module = filter_mod,
	});
	const run_filter_tests = b.addRunArtifact(filter_tests);

	const socks5_tests = b.addTest(.{
		.root_module = socks5_mod,
	});
	const run_socks5_tests = b.addRunArtifact(socks5_tests);

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

	const cli_test_mod = b.createModule(.{
		.root_source_file = b.path("src/cli/parse.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	const cli_tests = b.addTest(.{
		.root_module = cli_test_mod,
	});
	const run_cli_tests = b.addRunArtifact(cli_tests);

	const test_step = b.step("test", "Run unit tests");
	test_step.dependOn(&run_filter_tests.step);
	test_step.dependOn(&run_socks5_tests.step);
	test_step.dependOn(&run_rules_tests.step);
	test_step.dependOn(&run_cli_tests.step);
}
