# Standing bypass-test suite for the cogbox container-mode nft egress floor
# (TODO). Boots a guest, loads the REAL cogbox-nft-divert.sh ruleset against
# stub enforcer/resolver coordinates, then probes every egress path and asserts
# the FORCED-THROUGH / ALLOWED / DROPPED outcomes -- proving the DNS-tunnel, ICMP
# and non-tcp/udp-L4 leaks the old policy-accept floor permitted are now CLOSED.
#
# A full run needs nested KVM, so it does NOT execute in the dev sandbox; it runs
# in CI / on a KVM host via `nix build .#checks.x86_64-linux.nft-floor-bypass`.
# `nix flake check --no-build` / `nix eval .#checks...drvPath` only EVALUATE it.
{ self, pkgs }:
{
	name = "cogbox-nft-floor-bypass";

	nodes.machine = { lib, ... }: {
		virtualisation = {
			cores = 2;
			memorySize = 2048;
		};

		# `dummy` lets us pin every probe destination IP locally so the test is
		# fully hermetic (no real egress); the divert/floor OUTPUT hooks still
		# apply to locally-destined packets, which is exactly what we exercise.
		boot.kernelModules = [ "dummy" ];

		# Keep nothing else on udp/53 so the probe's stub-resolver listeners bind
		# the test ClusterIPs cleanly.
		services.resolved.enable = false;

		environment.systemPackages = with pkgs; [ nftables iproute2 iputils python3 ];

		# The probe connects to a NAME to prove name-based TCP is redirected too;
		# resolve it locally so the test needs no real DNS.
		networking.extraHosts = "192.0.2.20 origin.test";

		# Make the real artifacts available in the guest unchanged.
		environment.etc."cogbox-nft-divert.sh".source = ../cogbox-nft-divert.sh;
		environment.etc."nft_bypass_probe.py".source = ./nft_bypass_probe.py;
	};

	# Driver script is a column-0 .py file (matching tests/cogbox.nix) so the test
	# driver execs it verbatim -- a `''` block would leave Nix-stripped indentation.
	testScript = builtins.readFile ./nft_floor_bypass_driver.py;
}
