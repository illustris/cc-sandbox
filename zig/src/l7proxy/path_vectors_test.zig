// The Zig half of the SHARED L7 path-matching vector table.
//
// `path_vectors.tsv` is the single oracle for the two matchers that must agree:
// this proxy's `filter.pathPrefixMatches` (cleartext HTTP + the passthrough
// tier) and the mitmproxy addon's `path_match` (HTTPS terminate -- which is all
// git API traffic). The addon suite (`tests/test_l7_addon.py`) reads the SAME
// file, so a semantics change in either matcher fails its own suite, and
// "fixing" the table for one matcher immediately fails the other. That is the
// whole lockstep mechanism; there is no second copy to drift.
//
// Vectors run the REAL request-side pipeline -- `http.stripQuery` then
// `http.normalizePath` -- because the percent-decoding step is half of the
// property under test: an encoded slash becomes a genuine separator, so it can
// never be smuggled INSIDE a `*`.

const std = @import("std");
const t = std.testing;
const filter = @import("filter");
const http = @import("http.zig");

const vectors: []const u8 = @embedFile("path_vectors.tsv");

/// One parsed, non-comment row: the leading kind plus its tab-separated fields.
const Row = struct {
	kind: []const u8,
	fields: [5][]const u8,
	n: usize,
};

fn rows(it: *std.mem.SplitIterator(u8, .scalar)) ?Row {
	while (it.next()) |raw| {
		const line = std.mem.trim(u8, raw, " \r");
		if (line.len == 0 or line[0] == '#') continue;
		var f = std.mem.splitScalar(u8, line, '\t');
		var out = Row{ .kind = f.next() orelse continue, .fields = undefined, .n = 0 };
		while (f.next()) |v| {
			if (out.n == out.fields.len) break;
			out.fields[out.n] = v;
			out.n += 1;
		}
		return out;
	}
	return null;
}

test "shared path vectors: the request-side normalizer" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "norm")) continue;
		try t.expect(r.n >= 2);
		var buf: [4096]u8 = undefined;
		const got = http.normalizePath(http.stripQuery(r.fields[0]), &buf) orelse {
			std.debug.print("norm vector {s}: normalizePath refused it\n", .{r.fields[0]});
			return error.NormalizeRefused;
		};
		t.expectEqualStrings(r.fields[1], got) catch |e| {
			std.debug.print("norm vector failed for {s}\n", .{r.fields[0]});
			return e;
		};
		seen += 1;
	}
	try t.expect(seen >= 12);
}

// A `reject` row is a raw path the normalizer must REFUSE (the caller then
// denies). Refusal is what keeps the authorized string and the forwarded string
// from naming different resources -- see the dot-segment block in the table.
test "shared path vectors: the normalizer refuses dot segments" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "reject")) continue;
		try t.expect(r.n >= 1);
		var buf: [4096]u8 = undefined;
		if (http.normalizePath(http.stripQuery(r.fields[0]), &buf)) |got| {
			std.debug.print(
				"reject vector {s}: normalizePath ACCEPTED it as {s} -- the decision path and the forwarded path can now differ\n",
				.{ r.fields[0], got },
			);
			return error.NormalizeAccepted;
		}
		seen += 1;
	}
	try t.expect(seen >= 8);
}

test "shared path vectors: pathPrefixMatches" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "match")) continue;
		try t.expect(r.n >= 3);
		const want = std.mem.eql(u8, r.fields[0], "yes");
		if (!want and !std.mem.eql(u8, r.fields[0], "no")) return error.MalformedVector;
		const rule = r.fields[1];
		var buf: [4096]u8 = undefined;
		const req = http.normalizePath(http.stripQuery(r.fields[2]), &buf) orelse {
			std.debug.print("match vector {s}: normalizePath refused it\n", .{r.fields[2]});
			return error.NormalizeRefused;
		};
		const got = filter.pathPrefixMatches(rule, req);
		if (got != want) {
			std.debug.print(
				"path vector FAILED: rule={s} req={s} (normalized {s}) want={} got={} -- {s}\n",
				.{ rule, r.fields[2], req, want, got, if (r.n > 3) r.fields[3] else "" },
			);
			return error.VectorMismatch;
		}
		seen += 1;
	}
	try t.expect(seen >= 40);
}

// A typo'd kind would silently skip a whole class of vectors in BOTH suites --
// the one way the shared table could stop asserting without anyone noticing.
test "shared path vectors: every row is a known kind" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	while (rows(&it)) |r| {
		if (std.mem.eql(u8, r.kind, "norm") or std.mem.eql(u8, r.kind, "match") or
			std.mem.eql(u8, r.kind, "reject")) continue;
		std.debug.print("unknown vector kind {s}\n", .{r.kind});
		return error.UnknownVectorKind;
	}
}
