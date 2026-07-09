#!/usr/bin/env bash
# Bash side of cogbox: handles VM init, on-disk migration, runtime
# preparation, and the actual microvm launch. Invoked by the Zig
# `cogbox` binary with already-validated arguments; see the
# argument-parsing block below for the contract. Not meant to be invoked
# directly by users.
#
# Intentionally NO `set -e`: the script's EXIT trap is the canonical
# cleanup path (kill passt, remove runtime dir). With `set -e`, any
# transient subshell failure during long migrations would short-circuit
# bash before the VM gets a chance to launch -- and the original
# cogbox.sh ran without it for the same reason.

# -- Argument parsing (Zig has already validated everything) -------
# Inputs (all optional):
#   --name NAME           Instance name. Empty/absent = default instance.
#   --vcpu N              vCPU count override.
#   --mem N               Memory MB override.
#   --network MODE        full|none|rules. If absent, fall back to config.json.
#   --init-only           Run init steps but do not start the VM.
#   --no-auto-keys        On first init, leave authorized_keys empty and skip
#                         generating cogbox's own SSH identity.
#   --yes                 Skip the interactive harness-selection prompt.
INIT_ONLY=0
FLAG_VCPU=""
FLAG_MEM=""
FLAG_NETWORK=""
INSTANCE_NAME=""
AUTO_KEYS=1
ASSUME_YES=0
while [ $# -gt 0 ]; do
	case "$1" in
		--init-only) INIT_ONLY=1; shift ;;
		--no-auto-keys) AUTO_KEYS=0; shift ;;
		--yes|-y) ASSUME_YES=1; shift ;;
		--name) INSTANCE_NAME="$2"; shift 2 ;;
		--vcpu) FLAG_VCPU="$2"; shift 2 ;;
		--mem) FLAG_MEM="$2"; shift 2 ;;
		--network) FLAG_NETWORK="$2"; shift 2 ;;
		*) echo "cogbox-launch: error: unexpected argument $1 (Zig wrapper should have rejected this)" >&2; exit 70 ;;
	esac
done

# Reconstruct the cogbox argv for the custom-flake re-exec path below. The
# verb mirrors the current mode so the re-exec'd cogbox does the same thing
# without re-forking or re-prompting: `init` for --init-only, otherwise the
# hidden `__launch` verb (exec the launch script in place -- the
# daemonization was already done by the `start` verb that forked us, so we
# must not fork again).
if [ "$INIT_ONLY" -eq 1 ]; then
	ORIG_ARGS=(init)
else
	ORIG_ARGS=(__launch)
fi
[ -n "$INSTANCE_NAME" ] && ORIG_ARGS+=(--name "$INSTANCE_NAME")
[ -n "$FLAG_VCPU" ]     && ORIG_ARGS+=(--vcpu "$FLAG_VCPU")
[ -n "$FLAG_MEM" ]      && ORIG_ARGS+=(--mem "$FLAG_MEM")
[ -n "$FLAG_NETWORK" ]  && ORIG_ARGS+=(--network "$FLAG_NETWORK")
[ "$AUTO_KEYS" -eq 0 ]  && ORIG_ARGS+=(--no-auto-keys)
[ "$ASSUME_YES" -eq 1 ] && ORIG_ARGS+=(--yes)

# Scaffold written into each instance's config dir on first init. Also used
# by the re-exec check below: if the user hasn't edited flake.nix, the
# resulting microvm closure is identical to the baked-in default and we can
# skip the (network-dependent) `nix run` re-eval entirely.
# shellcheck disable=SC2016
SCAFFOLD_FLAKE='{
	description = "cogbox per-instance extensions";

	# `pkgs` in nixosModules.default below comes from cogbox'\''s nixpkgs.
	# To use a different nixpkgs, add an input here (e.g.
	# inputs.nixpkgs-custom.url = "...";) and reference it explicitly.
	# cogbox always overrides any "nixpkgs" input you declare to its
	# own, so use a different name (like nixpkgs-custom) to escape that.

	outputs = { self }: {
		nixosModules.default = { pkgs, lib, ... }: {
			# Add per-instance packages and modules here. Examples:
			#   environment.systemPackages = with pkgs; [ hbase openjdk21 ];
			#   system.extraDependencies  = with pkgs; [ hbase openjdk21 ];
		};
	};
}
'

die() {
	echo "cogbox-launch: error: $*" >&2
	exit "${2:-70}"
}

# Generate cogbox's own SSH keypair ($COGBOX_SSH_KEY{,.pub}) once, host-side, so
# `cogbox ssh` has a default identity that works out of the box without relying
# on the user's personal keys or agent. Idempotent: a no-op if the key already
# exists. Tolerant of a missing ssh-keygen (just contributes nothing). The
# pubkey is unioned into each VM's authorized_keys at launch time; the private
# key stays on the host (the data-dir root is never mounted into a VM).
ensure_cogbox_key() {
	[ -f "$COGBOX_SSH_KEY" ] && return 0
	command -v ssh-keygen >/dev/null 2>&1 || return 0
	mkdir -p "$BASE_DATA"
	ssh-keygen -t ed25519 -N '' -C "cogbox" -f "$COGBOX_SSH_KEY" >/dev/null 2>&1 || true
}

# -- Resolve real user for sudo context ----------------------------
# Trust SUDO_USER ONLY when we are actually running as root: that is the genuine
# `sudo cogbox` case, where we act on behalf of the invoking user and chown the
# files back to them. `sudo` exports SUDO_USER for EVERY invocation (even
# `sudo -u other`), and a non-login `su other` preserves it -- so without the
# euid==0 guard, running as one user with another's stale SUDO_USER in the env
# would resolve to the wrong home/uid (writing into a dir we can't touch). When
# not root, our own identity (id/$HOME) is authoritative. SUDO_INVOCATION is the
# single source of truth downstream (runtime dir, chown-back).
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
	SUDO_INVOCATION=1
	REAL_USER="$SUDO_USER"
	REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	REAL_UID=$(getent passwd "$SUDO_USER" | cut -d: -f3)
else
	SUDO_INVOCATION=0
	REAL_USER="$(id -un)"
	REAL_HOME="$HOME"
	REAL_UID="$(id -u)"
fi

# -- Paths (XDG basedir spec) --------------------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$REAL_HOME/.config}/cogbox"
BASE_DATA="${COGBOX_DATA:-${XDG_DATA_HOME:-$REAL_HOME/.local/share}/cogbox}"
# cogbox's own SSH identity, used as the default key for `cogbox ssh`. It lives
# in the data-dir root -- a sibling of instances/, which is the only subtree
# mounted into a VM -- so the private key never enters the sandbox. The Zig
# `ssh`/`start` verbs derive the same path; keep the basename in sync.
COGBOX_SSH_KEY="$BASE_DATA/cogbox_ed25519"
# Marker written when --no-auto-keys is chosen at first init. It makes that
# opt-out durable: without it a later plain `cogbox start` (AUTO_KEYS defaults
# to 1) would silently generate and authorize the key, re-enabling SSH the user
# opted out of. To opt in later, remove this file; to rotate, remove the key.
COGBOX_KEY_OPTOUT="$CONFIG_DIR/no-cogbox-key"

# Fail fast on an identity/permission mismatch instead of cascading mkdir/write
# failures into a corrupt half-init (and a misleading "invalid JSON" at start).
# The classic trigger is `sudo su <user>` WITHOUT `-`: that keeps the invoker's
# HOME/SUDO_USER, so the resolved home isn't writable by the user we now are.
if [ ! -d "$REAL_HOME" ] || [ ! -w "$REAL_HOME" ]; then
	die "resolved home '$REAL_HOME' (user '$REAL_USER') is not writable by uid $(id -u). If you switched users, use a login shell -- 'sudo su - $REAL_USER' (or 'sudo -u $REAL_USER env -u SUDO_USER HOME=$REAL_HOME ...') -- not 'sudo su $REAL_USER'." 78
fi

# -- Harness shape -------------------------------------------------
# The HARNESSES list is GENERATED from flake.nix's `mkHarnesses` set at
# build time: the cogbox package substitutes the harness-name sentinel below
# with the enabled-harness names, so this list always matches which harnesses
# the VM was built with -- including the opt-in `enableCodex`. The per-harness
# shape below (H_KIND, H_HOST, pathkeys, summaries, inject specs) is still
# hand-maintained and must mirror the matching harness attrs in flake.nix;
# names are used as 9p tags, fw_cfg keys, and runtime symlinks.
HARNESSES=(@harnesses@)
declare -A H_KIND
declare -A H_HOST
declare -A H_FW_DEFAULT
declare -A H_FW_MODE

H_KIND[claude-code:config]=overlay
H_HOST[claude-code:config]="${COGBOX_CLAUDE_CONFIG:-$REAL_HOME/.claude}"

H_KIND[claude-code:auth]=fw_cfg
H_HOST[claude-code:auth]="${COGBOX_CLAUDE_AUTH:-$REAL_HOME/.claude.json}"
H_FW_DEFAULT[claude-code:auth]='{}'
H_FW_MODE[claude-code:auth]=600

H_KIND[opencode:config]=overlay
H_HOST[opencode:config]="${COGBOX_OPENCODE_CONFIG:-${XDG_CONFIG_HOME:-$REAL_HOME/.config}/opencode}"

H_KIND[opencode:data]=overlay
H_HOST[opencode:data]="${COGBOX_OPENCODE_DATA:-${XDG_DATA_HOME:-$REAL_HOME/.local/share}/opencode}"

H_KIND[opencode:cache]=ephemeral
H_KIND[opencode:state]=ephemeral

H_KIND[codex:home]=overlay
H_HOST[codex:home]="${COGBOX_CODEX_HOME:-$REAL_HOME/.codex}"

H_KIND[hermes-agent:home]=overlay
H_HOST[hermes-agent:home]="${COGBOX_HERMES_HOME:-$REAL_HOME/.hermes}"

H_KIND[pi:home]=overlay
H_HOST[pi:home]="${COGBOX_PI_HOME:-$REAL_HOME/.pi}"

# Path keys per harness, in declared order.
harness_pathkeys() {
	case "$1" in
		claude-code) printf '%s\n' config auth ;;
		opencode) printf '%s\n' config data cache state ;;
		codex) printf '%s\n' home ;;
		hermes-agent) printf '%s\n' home ;;
		pi) printf '%s\n' home ;;
	esac
}

# Human-readable summary of what creating a harness's host state will
# do, used in the "set up which?" prompt.
harness_summary() {
	case "$1" in
		claude-code) echo "creates ~/.claude/, ~/.claude.json" ;;
		opencode)    echo "creates ~/.config/opencode/, ~/.local/share/opencode/" ;;
		codex)       echo "creates ~/.codex/" ;;
		hermes-agent) echo "creates ~/.hermes/" ;;
		pi)           echo "creates ~/.pi/" ;;
	esac
}

# -- Host-side credential injection (keep tokens out of the sandbox) ---
# Credential-injection specs per harness, one per line:
#   provider_host|style|cred_file|token_path|account_id_path|refresh_token_path|expires_at_path|token_url|client_id
# The terminate-tier mitmproxy addon reads token_path out of cred_file
# (host-side) and rewrites the request's auth header for provider_host, so the
# guest only ever carries a stub. cred_file is resolved from the same H_HOST
# paths used everywhere else. The trailing 4 fields are OPTIONAL and opt the
# host into host-side token refresh (the addon does the OAuth refresh-token
# grant when the access token nears expiry and writes the rotated tokens back
# to cred_file): needed for harnesses whose token is EVICTED from the guest
# (claude-code), since the guest then cannot refresh on its own. Harnesses that
# still carry their token in-guest refresh there and leave these blank. The
# OAuth login/refresh host (platform.claude.com) is deliberately NOT listed: the
# guest reaches it via the default L4 splice (passthrough), so an in-guest
# `/login` works AND the guest can refresh its OWN token there -- we never MITM
# or capture the login. See docs/network-filtering.md.
harness_inject_specs() {
	case "$1" in
		claude-code)
			printf '%s\n' \
				"api.anthropic.com|anthropic-oauth|${H_HOST[claude-code:config]}/.credentials.json|claudeAiOauth.accessToken||claudeAiOauth.refreshToken|claudeAiOauth.expiresAt|https://platform.claude.com/v1/oauth/token|9d1c250a-e61b-44d9-88ed-5944d1962f5e"
			;;
		codex)
			printf '%s\n' \
				"chatgpt.com|openai-chatgpt|${H_HOST[codex:home]}/auth.json|tokens.access_token|tokens.account_id" \
				"api.openai.com|openai-chatgpt|${H_HOST[codex:home]}/auth.json|tokens.access_token|tokens.account_id"
			;;
		opencode)
			# opencode is multi-provider; the anthropic OAuth provider is the
			# common case. API-key providers (openrouter/kimi) are not yet
			# auto-injected -- they keep the legacy guest-carries-token path.
			printf '%s\n' \
				"api.anthropic.com|anthropic-oauth|${H_HOST[opencode:data]}/auth.json|anthropic.access|"
			;;
	esac
}

# Deduped, cred-present inject specs for the active harnesses -- one TSV row per
# provider host, the single source both active_inject_hosts (the rule seed) and
# gen_inject_conf (the addon conf) project from, so their selection can't drift.
# Gating on cred existence (not just harness-active) avoids terminating a provider
# host for a harness with no token (the `--yes` init activates all harnesses, but
# most have no creds). First such harness wins a shared host (claude-code precedes
# opencode for api.anthropic.com in HARNESSES order). Fields, tab-separated:
#   host style cred token acct rtok exp turl cid stub_token
inject_specs_deduped() {
	local h host style cred token acct rtok exp turl cid
	declare -A seen
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS='|' read -r host style cred token acct rtok exp turl cid; do
			[ -z "$host" ] && continue
			[ -n "${seen[$host]:-}" ] && continue
			[ -f "$cred" ] || continue
			seen[$host]=1
			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
				"$host" "$style" "$cred" "$token" "$acct" "$rtok" "$exp" "$turl" "$cid" \
				"$(harness_stub_token "$h")"
		done < <(harness_inject_specs "$h")
	done
}

# Unique provider hosts to terminate+inject for the active harnesses the user is
# actually LOGGED INTO (host-side cred file present) -- the seed for a new
# instance's L7 rules.
active_inject_hosts() {
	inject_specs_deduped | cut -f1
}

# Emit the inject-conf (JSON array) for the active harnesses to stdout: one spec
# per deduped provider host whose host-side cred file EXISTS. `[]` if none -- the
# caller then writes no conf and the addon leaves auth untouched.
gen_inject_conf() {
	inject_specs_deduped | jq -R -s '
		[ split("\n")[] | select(length > 0) | split("\t")
		  | { host: .[0], style: .[1], cred_file: .[2], token_path: .[3] }
		  + (if (.[4] // "") != "" then { account_id_path: .[4] } else {} end)
		  + (if (.[5] // "") != "" and (.[6] // "") != ""
		         and (.[7] // "") != "" and (.[8] // "") != ""
		       then { refresh: { refresh_token_path: .[5], expires_at_path: .[6],
		                         token_url: .[7], client_id: .[8],
		                         expires_at_unit: "ms" } }
		       else {} end)
		  + (if (.[9] // "") != "" then { stub_token: .[9] } else {} end) ]
	'
}

# The secret file to scrub from the guest when injection is active, as
# "<overlay-pathkey> <basename>". When the harness defines a redactor (below) the
# file is REWRITTEN with its tokens replaced by placeholders but its non-secret
# fields kept; otherwise it is dropped wholesale. Either way the real
# access/refresh tokens never enter the sandbox -- the addon injects the real
# token host-side on the wire. Only claude-code is handled for now; codex
# (account id lives in the same file) and opencode (multi-provider, non-injected
# API-key providers) keep the mounted-token path until their redactors are built.
harness_secret_file() {
	case "$1" in
		claude-code) echo "config .credentials.json" ;;
	esac
}

# The placeholder access token harness_secret_redact_jq writes in place of the
# real one -- a recognizable SENTINEL. The inject addon stamps the real token
# ONLY over this exact stub (or an absent credential), so a SECONDARY credential
# the guest legitimately obtains through an injected call -- e.g. claude-code
# Remote Control's per-session "bridge credentials" used on
# /v1/code/sessions/<id>/worker + the SSE transport -- reaches the upstream
# UNTOUCHED instead of being clobbered with the OAuth token (which yields 401 /
# worker_register_failed -> "Transport closed (code 403)"). Emitted into the
# inject-conf as `stub_token` (gen_inject_conf). Empty => harness not redacted.
harness_stub_token() {
	case "$1" in
		claude-code) echo "sk-ant-oat01-cogbox-host-injected-placeholder" ;;
	esac
}

# jq program to REDACT (rather than drop) the secret file for a harness, or empty
# to fall back to full eviction. Keeping the non-secret fields -- the OAuth
# `scopes` and subscriptionType -- lets the harness still present a logged-in
# identity inside the guest (claude-code's `/remote-control`, for one, gates on a
# local full-scope credential), while the token fields become inert placeholders:
# the host proxy overwrites the access token on the wire (ONLY over the stub --
# see harness_stub_token), and a far-future expiry stops the guest from ever
# trying (and failing) to refresh the placeholder locally. The accessToken stub
# MUST equal harness_stub_token so the addon recognizes it. Fail-safe: if jq
# errors on an unexpected cred shape, staging drops the file entirely rather than
# risk writing a real token (see stage_overlay_source).
harness_secret_redact_jq() {
	local stub; stub="$(harness_stub_token "$1")"
	[ -z "$stub" ] && return
	case "$1" in
		claude-code) cat <<-JQ
		if (.claudeAiOauth | type) != "object" then error("unexpected cred shape")
		else .claudeAiOauth.accessToken = "$stub"
		   | .claudeAiOauth.refreshToken = "cogbox-evicted-no-refresh-token-in-guest"
		   | .claudeAiOauth.expiresAt = 9999999999000
		end
		JQ
		;;
	esac
}

# Write a minimal redacted-scoped PLACEHOLDER credential for a harness to $2.
# The staging-failure fallback: the guest must ALWAYS have a present, scoped,
# logged-in identity -- the addon injects the real token over the stub, and BOTH
# /remote-control (gates on a local full-scope cred file) and an in-guest /login
# need a present scoped file on disk. The accessToken is single-sourced from
# harness_stub_token (the SAME string the redactor writes and the addon matches),
# so it can never drift. Returns non-zero if the harness has no stub identity or
# the write fails; the caller then evicts the file (legacy behavior).
write_stub_cred() {
	local h=$1 dest=$2 stub
	stub="$(harness_stub_token "$h")"
	[ -z "$stub" ] && return 1
	case "$h" in
		claude-code)
			jq -n --arg t "$stub" '{claudeAiOauth: {accessToken: $t,
				refreshToken: "cogbox-evicted-no-refresh-token-in-guest",
				expiresAt: 9999999999000,
				scopes: ["user:inference", "user:profile"]}}' > "$dest" 2>/dev/null \
				|| return 1
			chmod 600 "$dest" 2>/dev/null || return 1
			;;
		*) return 1 ;;
	esac
}

# Stage the 9p source for an active harness overlay path: normally the real host
# dir, but when injection is active AND this path holds the harness's secret
# file, a per-instance hardlink-mirror in which that file is REDACTED -- tokens
# replaced by placeholders, non-secret fields kept (or omitted entirely if it
# can't be safely redacted; no bulk data copy -- the dir can be large). The
# mirror lives host-only under the cogbox data root
# ($BASE_DATA/mirrors/<instance>/); it must NOT go under REAL_DATA, which is
# shared RW into the guest -- the hardlinks alias the real host dir, so a guest
# write would corrupt it. Hardlinks need same-fs as the source (true when both
# sit under $HOME); a copy fallback covers the rare separate-mount case, and we
# fail closed to an empty dir, never the real dir. Echoes the path to share.
stage_overlay_source() {
	local h=$1 k=$2 host=$3
	local skey sfile
	read -r skey sfile <<< "$(harness_secret_file "$h")"
	if [ "$INJECT_ACTIVE" != "1" ] || [ -z "$sfile" ] || [ "$skey" != "$k" ] \
		|| [ ! -e "$host/$sfile" ]; then
		printf '%s' "$host"
		return
	fi
	local redact; redact="$(harness_secret_redact_jq "$h")"
	local mirror; mirror="$BASE_DATA/mirrors/${EFFECTIVE_NAME}/${h}-${k}"
	rm -rf "$mirror"; mkdir -p "$mirror"
	if cp -al "$host/." "$mirror/" 2>/dev/null || cp -a "$host/." "$mirror/" 2>/dev/null; then
		# Break the hardlink to the real cred file before touching it: the mirror
		# entry aliases the host's inode, so writing through it would corrupt the
		# user's real credential. rm drops only the mirror's link.
		rm -f "$mirror/$sfile"
		# Redact-in-place when the harness defines a redactor: rewrite the cred
		# file with its tokens replaced by placeholders but its non-secret fields
		# (OAuth scopes, ...) kept, so the harness still sees a logged-in identity
		# while the real tokens stay host-side. No redactor -- or a jq error on an
		# unexpected cred shape -- leaves the file GONE (full eviction), never the
		# real tokens. Direct-to-target then rm-on-failure is safe: the mirror is
		# host-only and not yet shared into any guest at staging time.
		if [ -n "$redact" ]; then
			if jq "$redact" "$host/$sfile" > "$mirror/$sfile" 2>/dev/null; then
				chmod 600 "$mirror/$sfile"
			else
				# Unexpected cred shape: stage a minimal scoped PLACEHOLDER rather
				# than evict -- a present scoped file keeps the inherit-default path
				# and /rc working (the addon injects the real token over the stub),
				# and lets the guest log in to its OWN account on top. Only if even
				# the placeholder can't be written do we evict (fail-safe: never the
				# real token).
				rm -f "$mirror/$sfile"
				if write_stub_cred "$h" "$mirror/$sfile"; then
					echo "cogbox-launch: warning: could not redact $h/$k secret; staged a placeholder identity instead (real token withheld)." >&2
				else
					rm -f "$mirror/$sfile"
					echo "cogbox-launch: warning: could not redact or stub $h/$k secret; evicting it entirely (token withheld)." >&2
				fi
			fi
		fi
		# Strip any token-bearing refresh write-temp the host-side refresh may
		# have left in the cred dir (crash residue, or a temp created during
		# this cp): it is a COMPLETE rotated credential (access + refresh token)
		# and must never reach the guest. Pattern matches CRED_TMP_PREFIX in
		# l7-mitm-addon.py. (The addon prefers a host-only temp dir off the
		# mirrored tree; this is the backstop for the same-fs fallback path.)
		rm -f "$mirror"/.cogbox-refresh-*.tmp 2>/dev/null || true
		printf '%s' "$mirror"
	else
		# Mirror failed: fail CLOSED -- never fall back to sharing the real dir
		# (that would leak the token). Stage a minimal scoped PLACEHOLDER cred so
		# the guest still has a present logged-in identity (host-side injection
		# fills in the real token over the stub); a harness with no stub identity
		# gets an empty dir.
		rm -rf "$mirror"; mkdir -p "$mirror"
		if [ -n "$redact" ] && write_stub_cred "$h" "$mirror/$sfile"; then
			echo "cogbox-launch: warning: could not mirror $h/$k dir; staged a placeholder identity only (real token withheld)." >&2
		else
			echo "cogbox-launch: warning: could not stage sanitized $h/$k mirror; sharing empty dir (token withheld)." >&2
		fi
		printf '%s' "$mirror"
	fi
}

# Microvm runner has runtime paths baked in at flake build time using this
# sentinel; the sed substitution below rewrites them to BASE_RUNTIME.
RUNTIME_TEMPLATE="@runtimeDir@"

# Per-user runtime dir per the XDG basedir spec. Under sudo, XDG_RUNTIME_DIR
# typically points at root's tree (or is unset); use the invoking user's
# /run/user/$UID instead. If that doesn't exist (no active logind session),
# fall back to /tmp/cogbox-runtime-$UID per the spec's "replacement
# directory with similar capabilities" guidance.
if [ "$SUDO_INVOCATION" = 1 ] || [ -z "${XDG_RUNTIME_DIR:-}" ]; then
	XDG_RUNTIME_BASE="/run/user/$REAL_UID"
else
	XDG_RUNTIME_BASE="$XDG_RUNTIME_DIR"
fi
if [ ! -d "$XDG_RUNTIME_BASE" ]; then
	XDG_RUNTIME_BASE="/tmp/cogbox-runtime-$REAL_UID"
	mkdir -p "$XDG_RUNTIME_BASE"
	chmod 700 "$XDG_RUNTIME_BASE"
fi
BASE_RUNTIME="$XDG_RUNTIME_BASE/cogbox"

EFFECTIVE_NAME="${INSTANCE_NAME:-default}"
INSTANCE_CONFIG_DIR="$CONFIG_DIR/instances/$EFFECTIVE_NAME"
# The flake lives in its own subdir so unrelated edits to config.json /
# authorized_keys don't bust the userExtensions flake's source hash.
INSTANCE_FLAKE_DIR="$INSTANCE_CONFIG_DIR/flake"
# Generated by `cogbox plugin` (DO NOT EDIT): composes every plugin's
# nixosModules.default plus the user flake above. Same own-subdir rationale.
PLUGINS_FLAKE_DIR="$INSTANCE_CONFIG_DIR/plugins-flake"
# Populated by `cogbox plugin` (file:// binary cache): the plugins re-exec
# below uses it as an extra substituter so a fresh-store launch resolves the
# composition's transitive tarball/narHash inputs offline.
PLUGIN_CACHE_DIR="$INSTANCE_CONFIG_DIR/plugin-cache"
REAL_DATA="$BASE_DATA/instances/$EFFECTIVE_NAME"
if [ -n "$INSTANCE_NAME" ]; then
	RUNTIME="${BASE_RUNTIME}-${INSTANCE_NAME}"
else
	RUNTIME="$BASE_RUNTIME"
fi

# Detect pre-fix layouts where the default instance's config and data
# lived at the top level of $CONFIG_DIR / $BASE_DATA, which nested every
# named instance inside the default (and exposed named-instance data to
# the default guest via 9p).
if [ -z "$INSTANCE_NAME" ]; then
	OLD_CFG=""; OLD_DATA=""
	[ -f "$CONFIG_DIR/config.json" ] && [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ] && OLD_CFG=1
	[ -e "$BASE_DATA/claude-overlay.img" ] && [ ! -d "$REAL_DATA" ] && OLD_DATA=1
	if [ -n "$OLD_CFG" ] || [ -n "$OLD_DATA" ]; then
		{
			echo "cogbox-launch: error: cogbox layout changed. The default instance now lives at:"
			echo "  config: $INSTANCE_CONFIG_DIR/"
			echo "  data:   $REAL_DATA/"
			echo "Migrate with:"
			if [ -n "$OLD_CFG" ]; then
				echo "  mkdir -p '$INSTANCE_CONFIG_DIR'"
				echo "  mv '$CONFIG_DIR/config.json' '$INSTANCE_CONFIG_DIR/'"
			fi
			if [ -n "$OLD_DATA" ]; then
				echo "  mkdir -p '$REAL_DATA'"
				echo "  mv '$BASE_DATA/claude-overlay.img' '$REAL_DATA/'"
				echo "  [ -d '$BASE_DATA/.config' ] && mv '$BASE_DATA/.config' '$REAL_DATA/'"
			fi
		} >&2
		exit 70
	fi
fi

# Detect pre-fix layouts where the per-instance flake.nix lived directly in
# the instance config dir. Sharing that dir with config.json meant any edit
# to config.json re-keyed the userExtensions flake input and busted the
# eval cache; the flake now lives in a "flake/" subdir.
if [ -d "$CONFIG_DIR/instances" ]; then
	OLD_FLAKES=()
	for dir in "$CONFIG_DIR/instances"/*/; do
		[ -d "$dir" ] || continue
		if [ -f "$dir/flake.nix" ] && [ ! -f "$dir/flake/flake.nix" ]; then
			OLD_FLAKES+=("${dir%/}")
		fi
	done
	if [ "${#OLD_FLAKES[@]}" -gt 0 ]; then
		{
			echo "cogbox-launch: error: cogbox flake layout changed. The per-instance flake now lives at:"
			echo "  <instance>/flake/flake.nix  (was: <instance>/flake.nix)"
			echo "Migrate with:"
			for d in "${OLD_FLAKES[@]}"; do
				echo "  mkdir -p '$d/flake'"
				if [ -f "$d/flake.lock" ]; then
					echo "  mv '$d/flake.nix' '$d/flake.lock' '$d/flake/'"
				else
					echo "  mv '$d/flake.nix' '$d/flake/'"
				fi
			done
		} >&2
		exit 70
	fi
fi

# Multi-harness migration: rename the per-instance overlay image from
# the old single-harness name. The image's content is preserved
# verbatim; the in-image upper/work shuffle into claude-code/config/
# is handled by harness-setup-dirs.service inside the guest.
if [ -d "$REAL_DATA" ] && [ -f "$REAL_DATA/claude-overlay.img" ] && [ ! -f "$REAL_DATA/harness-overlay.img" ]; then
	mv "$REAL_DATA/claude-overlay.img" "$REAL_DATA/harness-overlay.img"
fi

# -- Auto-port assignment -----------------------------------------
next_available_ports() {
	# Seeded one below the default's canonical 2222/8080, so the first
	# named instance auto-assigns to 2223/8081 even if the default does
	# not yet exist (i.e. 2222/8080 stays reserved for the default).
	local max_ssh=2222
	local max_http=8080
	# Seed one triple below the canonical L7 base so the first named instance
	# auto-assigns to 18446 (the default keeps 18443/18444/18445).
	local max_l7=18440

	if [ -d "$CONFIG_DIR/instances" ]; then
		for cfg in "$CONFIG_DIR/instances"/*/config.json; do
			[ -f "$cfg" ] || continue
			local s h l
			s=$(jq -r '.sshPort // 0' "$cfg")
			h=$(jq -r '.httpPort // 0' "$cfg")
			l=$(jq -r '.l7PortBase // 0' "$cfg")
			[ "$s" -gt "$max_ssh" ] && max_ssh=$s
			[ "$h" -gt "$max_http" ] && max_http=$h
			[ "$l" -gt "$max_l7" ] && max_l7=$l
		done
	fi

	# Each instance gets a contiguous L7 port triple (base / base+1 / base+2 =
	# TLS funnel / HTTP funnel / mitmproxy hop), so multiple L7 instances never
	# share a port. Step by 3 to keep triples disjoint.
	echo "$(( max_ssh + 1 )) $(( max_http + 1 )) $(( max_l7 + 3 ))"
}

# -- Harness state detection ---------------------------------------
# Active harnesses are those whose host state already exists. If none
# exist (fresh install), prompt the user to choose. The chosen list
# governs which harnesses' host paths get created during init.
ACTIVE_HARNESSES_FILE="$REAL_DATA/.config/active-harnesses"
ACTIVE_HARNESSES=()

# Detect harnesses that already have *any* host-side state (overlay or
# fw_cfg path present on disk, or already-active per a prior init).
for h in "${HARNESSES[@]}"; do
	active=0
	if [ -f "$ACTIVE_HARNESSES_FILE" ] && grep -qx "$h" "$ACTIVE_HARNESSES_FILE"; then
		active=1
	fi
	if [ "$active" -eq 0 ]; then
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			kind=${H_KIND[$h:$k]}
			[ "$kind" = "ephemeral" ] && continue
			host=${H_HOST[$h:$k]}
			if [ "$kind" = "overlay" ] && [ -d "$host" ]; then
				active=1; break
			fi
			if [ "$kind" = "fw_cfg" ] && [ -e "$host" ]; then
				active=1; break
			fi
		done < <(harness_pathkeys "$h")
	fi
	if [ "$active" -eq 1 ]; then
		ACTIVE_HARNESSES+=("$h")
	fi
done

# -- First-time init: collect missing items, prompt once -----------
ITEMS=()
if [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
	if [ -z "$INSTANCE_NAME" ]; then
		ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (default settings)")
	else
		ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (instance \"$INSTANCE_NAME\" settings)")
	fi
fi
if [ ! -f "$INSTANCE_FLAKE_DIR/flake.nix" ]; then
	ITEMS+=("$INSTANCE_FLAKE_DIR/flake.nix  (per-instance NixOS extensions, no-op default)")
fi
if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
	if [ "$AUTO_KEYS" -eq 1 ]; then
		ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, seeded from ~/.ssh/*.pub + ssh-add -L)")
	else
		ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, empty)")
	fi
fi
if [ "$AUTO_KEYS" -eq 1 ] && [ ! -f "$COGBOX_SSH_KEY" ] && command -v ssh-keygen >/dev/null 2>&1; then
	ITEMS+=("$COGBOX_SSH_KEY  (cogbox's own SSH key, the default identity for \`cogbox ssh\`)")
fi
if [ ! -d "$REAL_DATA" ]; then
	ITEMS+=("$REAL_DATA/  (VM data${INSTANCE_NAME:+ for \"$INSTANCE_NAME\"})")
fi

# If no harness has host state yet, prompt the user to pick which to
# set up. This avoids polluting $HOME with config dirs for tools the
# user doesn't use. Under a non-interactive stdin or with --yes, default
# to all harnesses.
if [ "${#ACTIVE_HARNESSES[@]}" -eq 0 ]; then
	if [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
		echo "No harness state detected. Set up which?"
		idx=1
		for h in "${HARNESSES[@]}"; do
			echo "  [$idx] $h     ($(harness_summary "$h"))"
			idx=$((idx + 1))
		done
		all_idx=$idx
		echo "  [$all_idx] all"
		num_harnesses=${#HARNESSES[@]}
		read -rp "Choice [1-$all_idx, comma-separated for multiple]: " choice
		# Strip whitespace.
		choice="${choice// /}"
		if [ -z "$choice" ]; then
			die "Invalid choice." 64
		fi
		if [ "$choice" = "$all_idx" ]; then
			ACTIVE_HARNESSES=("${HARNESSES[@]}")
		else
			# Comma-separated indices, deduped while preserving order.
			IFS=',' read -ra picks <<< "$choice"
			declare -A seen=()
			for p in "${picks[@]}"; do
				case "$p" in ''|*[!0-9]*) die "Invalid choice." 64 ;; esac
				if [ "$p" -lt 1 ] || [ "$p" -gt "$num_harnesses" ]; then
					die "Invalid choice." 64
				fi
				h="${HARNESSES[$((p - 1))]}"
				if [ -z "${seen[$h]:-}" ]; then
					ACTIVE_HARNESSES+=("$h")
					seen[$h]=1
				fi
			done
		fi
	else
		ACTIVE_HARNESSES=("${HARNESSES[@]}")
	fi
fi

# Collect host paths to be created for active harnesses.
for h in "${ACTIVE_HARNESSES[@]}"; do
	while IFS= read -r k; do
		[ -z "$k" ] && continue
		kind=${H_KIND[$h:$k]}
		[ "$kind" = "ephemeral" ] && continue
		host=${H_HOST[$h:$k]}
		case "$kind" in
			overlay)
				if [ ! -d "$host" ]; then
					ITEMS+=("$host/  ($h $k)")
				fi
				;;
			fw_cfg)
				if [ ! -e "$host" ]; then
					ITEMS+=("$host  ($h $k)")
				fi
				;;
		esac
	done < <(harness_pathkeys "$h")
done

if [ "${#ITEMS[@]}" -gt 0 ]; then
	echo "The following paths will be created:"
	for item in "${ITEMS[@]}"; do
		echo "  $item"
	done
	echo ""
	if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ]; then
		confirm=y
	else
		read -rp "Continue? [y/N] " confirm
	fi
	if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
		echo "Aborted."
		exit 70
	fi

	mkdir -p "$INSTANCE_CONFIG_DIR" "$INSTANCE_FLAKE_DIR" "$REAL_DATA"

	# Create host-side directories for active harnesses' overlay paths.
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			kind=${H_KIND[$h:$k]}
			[ "$kind" = "overlay" ] || continue
			host=${H_HOST[$h:$k]}
			[ -d "$host" ] || mkdir -p "$host"
		done < <(harness_pathkeys "$h")
	done

	INIT_VCPU="${FLAG_VCPU:-16}"
	INIT_MEM="${FLAG_MEM:-32768}"
	INIT_NETWORK="${FLAG_NETWORK:-rules}"

	# Build network value for config: "full"/"none" as string, rules as object.
	# Default rules seed denies private/bogon ranges then allows public internet,
	# so a fresh install gets working internet without exposing LAN or cloud
	# metadata services to the sandbox. Loopback is omitted -- already denied
	# implicitly in filter.zig.
	if [ "$INIT_NETWORK" = "rules" ]; then
		# Seed L7 terminate+inject rules for the provider hosts of harnesses the
		# user is logged into (cred file present), so a new rules-mode instance
		# keeps tokens host-side by default (the chosen posture). Nothing is
		# seeded for a harness with no token yet; log in on the host first, or add
		# the rule later. Opt out by `cogbox l7 mode passthrough`, per-host
		# `cogbox l7 add allow <host> --passthrough`, or editing `.network.l7`.
		L7_SEED_JQ='null'
		if [ "${#ACTIVE_HARNESSES[@]}" -gt 0 ]; then
			_inject_hosts=$(active_inject_hosts)
			if [ -n "$_inject_hosts" ]; then
				L7_SEED_JQ=$(printf '%s\n' "$_inject_hosts" | jq -R -s '
					{ inject: true,
					  rules: [ split("\n")[] | select(length > 0)
					           | { allow: ., terminate: true, comment: "cred-inject (host-side)" } ] }')
			fi
		fi
		NETWORK_JQ=$(jq -nc --argjson l7 "$L7_SEED_JQ" '{
			rules: [
				{deny:  "0.0.0.0/8",        comment: "this network (RFC 1122)"},
				{deny:  "10.0.0.0/8",       comment: "RFC1918 private"},
				{deny:  "100.64.0.0/10",    comment: "carrier-grade NAT (RFC 6598)"},
				{deny:  "169.254.0.0/16",   comment: "link-local incl. cloud metadata 169.254.169.254"},
				{deny:  "172.16.0.0/12",    comment: "RFC1918 private"},
				{deny:  "192.0.0.0/24",     comment: "IETF protocol assignments (RFC 6890)"},
				{deny:  "192.0.2.0/24",     comment: "TEST-NET-1 documentation (RFC 5737)"},
				{deny:  "192.168.0.0/16",   comment: "RFC1918 private"},
				{deny:  "198.18.0.0/15",    comment: "benchmark testing (RFC 2544)"},
				{deny:  "198.51.100.0/24",  comment: "TEST-NET-2 documentation (RFC 5737)"},
				{deny:  "203.0.113.0/24",   comment: "TEST-NET-3 documentation (RFC 5737)"},
				{deny:  "224.0.0.0/4",      comment: "multicast (RFC 5771)"},
				{deny:  "240.0.0.0/4",      comment: "reserved/broadcast incl. 255.255.255.255"},
				{allow: "0.0.0.0/0",        comment: "public internet"}
			]
		} + (if $l7 != null then { l7: $l7 } else {} end)')
	else
		NETWORK_JQ="\"$INIT_NETWORK\""
	fi

	if [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
		if [ -z "$INSTANCE_NAME" ]; then
			INIT_SSH=2222
			INIT_HTTP=8080
			INIT_L7=18443
		else
			read -r INIT_SSH INIT_HTTP INIT_L7 <<< "$(next_available_ports)"
		fi
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--argjson network "$NETWORK_JQ" \
			--argjson ssh "$INIT_SSH" \
			--argjson http "$INIT_HTTP" \
			--argjson l7base "$INIT_L7" \
			'{
				vcpu: $vcpu,
				mem: $mem,
				sshPort: $ssh,
				httpPort: $http,
				l7PortBase: $l7base,
				overlaySize: "128M",
				storeOverlaySize: "16G",
				bindAddr: "127.0.0.1",
				network: $network
			}' > "$INSTANCE_CONFIG_DIR/config.json"
		[ -n "$INSTANCE_NAME" ] && echo "Instance \"$INSTANCE_NAME\" ports: SSH=$INIT_SSH HTTP=$INIT_HTTP L7=$INIT_L7"
	fi

	if [ ! -f "$INSTANCE_FLAKE_DIR/flake.nix" ]; then
		printf '%s' "$SCAFFOLD_FLAKE" > "$INSTANCE_FLAKE_DIR/flake.nix"
	fi

	if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
		if [ "$AUTO_KEYS" -eq 1 ]; then
			# Seed from the host user's existing pubkeys and any keys loaded
			# in their running ssh-agent (if SSH_AUTH_SOCK is set). Errors
			# are tolerated: missing ~/.ssh, no .pub files, or no agent all
			# just contribute zero lines. Result is sorted/deduped so the
			# same key from both sources doesn't appear twice.
			{
				if [ -d "$REAL_HOME/.ssh" ]; then
					for f in "$REAL_HOME/.ssh"/*.pub; do
						[ -f "$f" ] && cat "$f"
					done
				fi
				if [ -n "${SSH_AUTH_SOCK:-}" ] && command -v ssh-add >/dev/null; then
					ssh-add -L 2>/dev/null || true
				fi
			} | grep -v '^[[:space:]]*\(#\|$\)' | sort -u > "$CONFIG_DIR/authorized_keys"
		else
			touch "$CONFIG_DIR/authorized_keys"
			# Record the opt-out so subsequent plain launches don't generate the
			# cogbox key and re-authorize SSH access against the user's intent.
			touch "$COGBOX_KEY_OPTOUT"
		fi
	fi
	# Seed default content for fw_cfg paths (e.g. ~/.claude.json = '{}').
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			[ "${H_KIND[$h:$k]}" = "fw_cfg" ] || continue
			host=${H_HOST[$h:$k]}
			[ -e "$host" ] && continue
			printf '%s' "${H_FW_DEFAULT[$h:$k]}" > "$host"
			chmod "${H_FW_MODE[$h:$k]}" "$host"
		done < <(harness_pathkeys "$h")
	done
fi

# Persist the active-harness list so subsequent runs don't re-prompt.
mkdir -p "$REAL_DATA/.config"
printf '%s\n' "${ACTIVE_HARNESSES[@]}" > "$ACTIVE_HARNESSES_FILE"

# Generate cogbox's own SSH key (idempotent). Runs every launch, not just first
# init, so instances created before this feature gain it on the next start and a
# deleted key is regenerated (rotation). Skipped under --no-auto-keys for this
# launch, and permanently for a setup that opted out at init (the marker).
if [ "$AUTO_KEYS" -eq 1 ] && [ ! -f "$COGBOX_KEY_OPTOUT" ]; then
	ensure_cogbox_key
fi

# -- Fix file ownership after init under sudo ----------------------
if [ "$SUDO_INVOCATION" = 1 ]; then
	chown -R "$REAL_USER" "$CONFIG_DIR" "$REAL_DATA"
	# The key lives in the data-dir root, outside the chown -R above; without
	# this it would stay root-owned and ssh would refuse it as the real user.
	[ -f "$COGBOX_SSH_KEY" ] && chown "$REAL_USER" "$COGBOX_SSH_KEY" "$COGBOX_SSH_KEY.pub"
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			kind=${H_KIND[$h:$k]}
			[ "$kind" = "ephemeral" ] && continue
			host=${H_HOST[$h:$k]}
			[ -e "$host" ] || continue
			if [ -d "$host" ]; then
				chown -R "$REAL_USER" "$host"
			else
				chown "$REAL_USER" "$host"
			fi
		done < <(harness_pathkeys "$h")
	done
fi

# -- Re-exec with per-instance extensions overlaid ----------------
# Two sources of guest extension, checked in priority order; both fold
# in via --override-input userExtensions so the rebuilt microvm runner
# includes the extra modules. COGBOX_REEXECED breaks the loop after the
# first hop.
#
#  1. plugins-flake/ -- generated by `cogbox plugin` whenever config.json
#     has a non-empty .plugins array. It composes every plugin (inputs
#     pinned by rev and/or narHash) PLUS the user flake, so it subsumes
#     case 2.
#     The user flake's "nixpkgs" input is still forced to cogbox's
#     nixpkgs, now one level deeper (userExtensions/user/nixpkgs).
#  2. flake/flake.nix edited away from the scaffold. Skipped while the
#     scaffold is pristine: its nixosModules.default is empty, so the
#     microvm closure would be identical to the baked-in one anyway --
#     and re-evaluating the cogbox flake requires its inputs to be
#     fetchable, which a fresh "nix profile install" or
#     NixOS-systemPackages setup may not have locally cached. Users who
#     customize flake.nix (or add plugins) opt into the re-eval. `cmp`
#     is byte-exact and avoids the trailing-newline trim that command
#     substitution does.
#
# Where the runner comes from: the microvm "run" script (line ~1326) is
# generated from "$RUNNER_DIR/bin/microvm-run". RUNNER_DIR defaults to the
# baked @runner@ sentinel (the plugin-less, image-default runner). The
# re-exec below rebuilds cogbox with the plugins overlaid so the rebuilt
# wrapper's @runner@ is the plugin-composed runner; that pass then points
# RUNNER_DIR at it. The plugins re-exec re-evaluates the ENTIRE cogbox NixOS
# config every boot (~100s cold) because --override-input marks the flake
# mutable and disables nix's eval cache.
RUNNER_DIR="${RUNNER_DIR:-@runner@}"
# Self-recorded fast path (plugins only). Once a plugins re-exec has built the
# composed runner, it writes its out-path here so the NEXT boot can realize
# that store path directly -- no flake eval. The file lives on the state PVC
# (under INSTANCE_CONFIG_DIR), so it persists across boots. Two lines:
#   line1 = the cogbox flakeSource (image rev) the runner was built against;
#   line2 = the composed runner out-path.
RUNNER_PATH_FILE="$INSTANCE_CONFIG_DIR/runner.path"
FAST_PATH=0

if [ -z "${COGBOX_REEXECED:-}" ]; then
	PLUGIN_COUNT=0
	if [ -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
		PLUGIN_COUNT=$(jq -r '(.plugins // []) | length' "$INSTANCE_CONFIG_DIR/config.json" 2>/dev/null || echo 0)
	fi
	# Substituter options shared by both re-exec branches and the fast-path
	# realise below (this nix invocation only). The per-instance file:// plugin
	# cache resolves transitive tarball/narHash inputs offline; require-sigs
	# false is safe there: a file:// cache is content-addressed and nix still
	# verifies narHash; a local trusted cache is just unsigned. When cogworx
	# configured a remote runner cache (COGBOX_EXTRA_* / COGBOX_NETRC_FILE) the
	# worker pod pre-built and pushed the microvm runner closure there, so boot
	# substitutes it instead of rebuilding from source. Each remote knob is a
	# no-op when its env var is empty/unset (byte-identical to the pre-cache
	# behavior).
	PLUGIN_SUBST_OPTS=()
	SUBSTITUTERS=""
	if [ -d "$PLUGIN_CACHE_DIR" ]; then
		SUBSTITUTERS="file://$PLUGIN_CACHE_DIR"
	fi
	if [ -n "${COGBOX_EXTRA_SUBSTITUTERS:-}" ]; then
		SUBSTITUTERS="${SUBSTITUTERS:+$SUBSTITUTERS }$COGBOX_EXTRA_SUBSTITUTERS"
	fi
	if [ -n "$SUBSTITUTERS" ]; then
		PLUGIN_SUBST_OPTS+=(--option extra-substituters "$SUBSTITUTERS" --option require-sigs false)
	fi
	if [ -n "${COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS:-}" ]; then
		PLUGIN_SUBST_OPTS+=(--option extra-trusted-public-keys "$COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS")
	fi
	if [ -n "${COGBOX_NETRC_FILE:-}" ]; then
		PLUGIN_SUBST_OPTS+=(--option netrc-file "$COGBOX_NETRC_FILE")
	fi

	# -- Skip-eval fast path (plugins only) ---------------------------
	# If a previous plugins re-exec recorded a runner out-path for THIS image
	# rev, realize that store path directly and skip the re-exec/eval entirely.
	# This is strictly an optimization and MUST be fail-safe: on any problem
	# (no record, rev marker mismatch, realise fails, run script absent) we
	# leave FAST_PATH=0 and fall through to the normal re-exec/eval path, which
	# re-records the (possibly new) rev -- so the path self-heals across image
	# upgrades.
	if [ "$PLUGIN_COUNT" -gt 0 ] && [ -f "$RUNNER_PATH_FILE" ]; then
		FP_REV="" FP_RUNNER=""
		{ IFS= read -r FP_REV; IFS= read -r FP_RUNNER; } < "$RUNNER_PATH_FILE" || true
		# Only trust the record when it was written against the current image
		# rev (@flakeSource@ expands to this cogbox's source store path).
		if [ "$FP_REV" = "@flakeSource@" ] && [ -n "$FP_RUNNER" ]; then
			if [ -e "$FP_RUNNER/bin/microvm-run" ]; then
				RUNNER_DIR="$FP_RUNNER"
				FAST_PATH=1
			elif nix-store --realise "${PLUGIN_SUBST_OPTS[@]}" "$FP_RUNNER" >/dev/null 2>&1 \
				&& [ -e "$FP_RUNNER/bin/microvm-run" ]; then
				RUNNER_DIR="$FP_RUNNER"
				FAST_PATH=1
			fi
		fi
	fi
fi

if [ -z "${COGBOX_REEXECED:-}" ] && [ "$FAST_PATH" -ne 1 ]; then
	if [ "$PLUGIN_COUNT" -gt 0 ] && [ -f "$PLUGINS_FLAKE_DIR/flake.nix" ]; then
		exec env COGBOX_REEXECED=1 nix \
			--extra-experimental-features "nix-command flakes" \
			"${PLUGIN_SUBST_OPTS[@]}" \
			run "path:@flakeSource@" \
			--override-input userExtensions "path:$PLUGINS_FLAKE_DIR" \
			--override-input userExtensions/user/nixpkgs "path:@nixpkgsSource@" \
			-- "${ORIG_ARGS[@]}"
	elif [ "$PLUGIN_COUNT" -gt 0 ]; then
		echo "Error: config.json lists $PLUGIN_COUNT plugin(s) but $PLUGINS_FLAKE_DIR/flake.nix is missing." >&2
		echo "Run 'cogbox plugin update' to regenerate it." >&2
		exit 70
	elif [ -f "$INSTANCE_FLAKE_DIR/flake.nix" ] \
		&& ! printf '%s' "$SCAFFOLD_FLAKE" | cmp -s - "$INSTANCE_FLAKE_DIR/flake.nix"; then
		exec env COGBOX_REEXECED=1 nix \
			--extra-experimental-features "nix-command flakes" \
			"${PLUGIN_SUBST_OPTS[@]}" \
			run "path:@flakeSource@" \
			--override-input userExtensions "path:$INSTANCE_FLAKE_DIR" \
			--override-input userExtensions/nixpkgs "path:@nixpkgsSource@" \
			-- "${ORIG_ARGS[@]}"
	fi
fi

# -- Self-record the composed runner for the next boot's fast path -
# Reached here in the re-exec'd (eval) pass, @runner@/@flakeSource@ have been
# substituted to THIS rev's freshly-built values, so the record is always
# correct for the current image. Only the plugins case is fast-pathed, so only
# record when the plugins flake drove this re-exec (a customized 0-plugin flake
# re-exec stays on the eval path). Best-effort: a write failure must not abort
# boot, hence the `|| true`.
if [ -n "${COGBOX_REEXECED:-}" ] && [ -f "$PLUGINS_FLAKE_DIR/flake.nix" ]; then
	printf '%s\n%s\n' "@flakeSource@" "@runner@" > "$RUNNER_PATH_FILE" 2>/dev/null || true
fi

# -- init-only stops here ------------------------------------------
# By this point host state is seeded and (for a customized per-instance
# flake) the runner has been built via the re-exec above, warming the cache
# for the daemon launch. Runtime-dir setup and the VM launch belong to the
# daemon, so `cogbox init` and the foreground init step both stop here.
if [ "$INIT_ONLY" -eq 1 ]; then
	echo "Init complete${INSTANCE_NAME:+ (instance \"$INSTANCE_NAME\")}."
	exit 0
fi

# -- Validate and read runtime config -----------------------------
ACTIVE_CONFIG="$INSTANCE_CONFIG_DIR/config.json"
if ! jq empty "$ACTIVE_CONFIG" 2>/dev/null; then
	die "invalid JSON in $ACTIVE_CONFIG" 70
fi

VCPU="${FLAG_VCPU:-$(jq -r '.vcpu // 16' "$ACTIVE_CONFIG")}"
MEM="${FLAG_MEM:-$(jq -r '.mem // 32768' "$ACTIVE_CONFIG")}"
SSH_PORT=$(jq -r '.sshPort // 2222' "$ACTIVE_CONFIG")
HTTP_PORT=$(jq -r '.httpPort // 8080' "$ACTIVE_CONFIG")
# Per-instance L7 loopback port base (default = canonical 18443 for instances
# created before per-instance ports existed). The proxy binds base/base+1 and
# reaches the mitmproxy terminate backend on base+2; mirrors filter.l7PortsForBase.
L7_BASE=$(jq -r '.l7PortBase // 18443' "$ACTIVE_CONFIG")
L7_MITM_PORT=$(( L7_BASE + 2 ))
OVERLAY_SIZE=$(jq -r '.overlaySize // "128M"' "$ACTIVE_CONFIG")
STORE_OVERLAY_SIZE=$(jq -r '.storeOverlaySize // "16G"' "$ACTIVE_CONFIG")
BIND_ADDR=$(jq -r '.bindAddr // "127.0.0.1"' "$ACTIVE_CONFIG")

# -- Classify network mode -----------------------------------------
if [ -n "$FLAG_NETWORK" ]; then
	NETWORK_MODE="$FLAG_NETWORK"
else
	NETWORK_RAW=$(jq -c '.network // "full"' "$ACTIVE_CONFIG")
	if [ "$NETWORK_RAW" = '"full"' ] || [ "$NETWORK_RAW" = '"none"' ]; then
		NETWORK_MODE=$(echo "$NETWORK_RAW" | tr -d '"')
	else
		NETWORK_MODE="rules"
	fi
fi

# -- Write VM-side config into the data directory ------------------
mkdir -p "$REAL_DATA/.config"
echo "$OVERLAY_SIZE" > "$REAL_DATA/.config/overlay-size"
echo "$STORE_OVERLAY_SIZE" > "$REAL_DATA/.config/store-overlay-size"
# The VM's authorized_keys is the user-managed file (per-instance override, else
# the shared one) unioned with cogbox's own pubkey, so `cogbox ssh` works out of
# the box. The union is keyed on the key file's existence, not the AUTO_KEYS
# flag: once generated the key is always honored, and a --no-auto-keys-only
# setup (no key file) gets exactly its user-provided keys.
if [ -n "$INSTANCE_NAME" ] && [ -f "$INSTANCE_CONFIG_DIR/authorized_keys" ]; then
	AUTHKEYS_SRC="$INSTANCE_CONFIG_DIR/authorized_keys"
else
	AUTHKEYS_SRC="$CONFIG_DIR/authorized_keys"
fi
# The `echo` between the two sources forces a record boundary: a user-managed
# authorized_keys with no trailing newline would otherwise splice its last key
# onto the cogbox pubkey, corrupting both. The grep then drops the resulting
# blank line(s) (and any comment/blank lines); sort -u dedupes.
{
	[ -f "$AUTHKEYS_SRC" ] && cat "$AUTHKEYS_SRC"
	echo
	[ -f "$COGBOX_SSH_KEY.pub" ] && cat "$COGBOX_SSH_KEY.pub"
} | grep -v '^[[:space:]]*\(#\|$\)' | sort -u > "$REAL_DATA/.config/authorized_keys"

# -- Set up runtime symlink directory for QEMU ---------------------
# Single-starter guard. The lock lives beside (not inside) $RUNTIME so the
# rm -rf below cannot clear it. Two near-simultaneous `cogbox start` for the
# same instance would otherwise both wipe + recreate $RUNTIME and boot two
# QEMUs against the same overlay image (corruption).
#
# We hold an exclusive flock on $LOCK for this daemon's ENTIRE lifetime: the
# fd stays open through the final `wait "$QEMU_PID"`, so the kernel keeps the
# lock until the daemon (and the QEMU/passt it spawned, which inherit the fd)
# is gone. flock -n fails immediately for any concurrent or already-running
# starter -> exit 75. This is race-free where the old pid-file dance was not:
# the kernel arbitrates the single winner atomically, and a crashed start
# releases the lock automatically (fd closed on death) with no stale-pid
# bookkeeping to get wrong.
LOCK="${RUNTIME}.lock"
exec {LOCK_FD}>"$LOCK" || die "cannot open start lock $LOCK" 70
if ! @flock@ -n "$LOCK_FD"; then
	die "instance${INSTANCE_NAME:+ \"$INSTANCE_NAME\"} is already running or starting." 75
fi

if [ -e "$RUNTIME" ]; then
	if [ -f "$RUNTIME/pid" ] && kill -0 "$(cat "$RUNTIME/pid")" 2>/dev/null; then
		die "instance${INSTANCE_NAME:+ \"$INSTANCE_NAME\"} is already running (PID $(cat "$RUNTIME/pid"))." 75
	fi
	rm -rf "$RUNTIME"
fi
mkdir -p "$RUNTIME"

# `cogbox start` opened our stdout/stderr on $RUNTIME/cogbox.log before
# exec'ing us, but the rm -rf above unlinked that inode. Reopen the fresh
# cogbox.log so daemon diagnostics (passt, QEMU stderr, errors below) are
# actually captured. Only when daemonized (stdout is the log file, not a
# tty); a hand-run launch keeps writing to its terminal.
if [ ! -t 1 ]; then
	exec >>"$RUNTIME/cogbox.log" 2>&1
fi

echo "$$" > "$RUNTIME/pid"

# -- Ensure the host ports we are about to bind are actually free ----
# next_available_ports keeps ports disjoint among THIS user's instances, but
# passt forwards SSH/HTTP and the L7 proxy + mitmproxy bind on the host's
# SHARED loopback -- so on a multi-user host a DIFFERENT user's instance (or
# any unrelated process) may already hold them. The bind would then fail and
# the start abort (fail-closed). Probe what we are about to bind and, if taken,
# slide to the next free port/triple, then persist so __render-rules (which
# reads l7PortBase back from config.json) and future launches agree.
# The probe is a loopback connect, so it catches the common conflict (another
# instance's passt/proxy listening on 0.0.0.0 or 127.0.0.1). A listener bound to
# ONLY a specific non-loopback host IP isn't seen here; passt's own bind would
# still surface that as a (now diagnosable) failure rather than a silent boot.
port_taken() {
	# 0 (true) when a TCP listener answers at $1:$2 within ~1s -- i.e. we could
	# not bind it. bash's /dev/tcp connect succeeds iff something is listening;
	# a refused connect (free port) returns immediately. The 1s timeout bounds
	# the case where bindAddr is a non-loopback host IP and a DROP (not REJECT)
	# firewall rule silently swallows the SYN -- an un-timed connect would then
	# block for the full kernel retry window (~2 min) per port, stalling the
	# (flock-holding) daemon. An indeterminate probe is treated as free; a real
	# late conflict is still caught by the bind itself, which now fails loud.
	timeout 1 bash -c '(exec 3<>"/dev/tcp/$1/$2")' _ "$1" "$2" 2>/dev/null
}
next_free_port() {
	# First free port >= $1 on address $2, scanning upward.
	local p=$1 addr=$2
	while [ "$p" -le 65500 ] && port_taken "$addr" "$p"; do p=$((p + 1)); done
	echo "$p"
}
next_free_l7_base() {
	# First base >= $1 (stepping by 3 so triples stay disjoint, mirroring
	# next_available_ports) whose whole loopback triple base/+1/+2 is free.
	local b=$1
	while [ "$b" -le 65000 ] && { port_taken 127.0.0.1 "$b" || port_taken 127.0.0.1 $((b + 1)) || port_taken 127.0.0.1 $((b + 2)); }; do
		b=$((b + 3))
	done
	echo "$b"
}
PORTS_CHANGED=0
_new=$(next_free_port "$SSH_PORT" "$BIND_ADDR")
if [ "$_new" != "$SSH_PORT" ]; then
	echo "cogbox-launch: SSH port $SSH_PORT ($BIND_ADDR) in use; using $_new instead." >&2
	SSH_PORT=$_new; PORTS_CHANGED=1
fi
_new=$(next_free_port "$HTTP_PORT" "$BIND_ADDR")
if [ "$_new" != "$HTTP_PORT" ]; then
	echo "cogbox-launch: HTTP port $HTTP_PORT ($BIND_ADDR) in use; using $_new instead." >&2
	HTTP_PORT=$_new; PORTS_CHANGED=1
fi
if [ "$NETWORK_MODE" = "rules" ]; then
	_new=$(next_free_l7_base "$L7_BASE")
	if [ "$_new" != "$L7_BASE" ]; then
		echo "cogbox-launch: L7 port base $L7_BASE in use; using $_new instead." >&2
		L7_BASE=$_new; L7_MITM_PORT=$((L7_BASE + 2)); PORTS_CHANGED=1
	fi
fi
if [ "$PORTS_CHANGED" -eq 1 ]; then
	# Persist atomically. __render-rules below reads l7PortBase from config, so
	# config MUST reflect the new base before it runs -- otherwise the netfilter
	# funnel and the proxy would point at different ports.
	_cfg_tmp=$(mktemp "${ACTIVE_CONFIG}.XXXXXX") || die "cannot create temp file to persist reallocated ports"
	if jq --tab --argjson ssh "$SSH_PORT" --argjson http "$HTTP_PORT" --argjson l7 "$L7_BASE" \
		'.sshPort = $ssh | .httpPort = $http | .l7PortBase = $l7' "$ACTIVE_CONFIG" > "$_cfg_tmp"; then
		mv "$_cfg_tmp" "$ACTIVE_CONFIG"
		[ "$SUDO_INVOCATION" = 1 ] && chown "$REAL_USER" "$ACTIVE_CONFIG"
	else
		rm -f "$_cfg_tmp"
		die "failed to persist reallocated ports to $ACTIVE_CONFIG"
	fi
fi

# Snapshot the active SSH endpoint for the `ssh` subcommand to read.
# Bound to runtime, not config, so post-boot edits to config.json don't
# misdirect connections to a port the VM isn't listening on.
echo "$SSH_PORT $BIND_ADDR" > "$RUNTIME/ssh-endpoint"
PASST_PID=""
L7PROXY_PID=""
L7MITM_PID=""
QEMU_PID=""
CLEANED=0
# The VM is always a background daemon now, so this script's only job after
# launch is to babysit QEMU and clean up. Forwarding the signal to QEMU (the
# wait target) is what makes `cogbox stop` tear the VM down: previously QEMU
# ran in this script's foreground and a SIGTERM here never reached it. We
# SIGTERM QEMU, give it a few seconds to flush + exit, then SIGKILL, and only
# then remove the runtime dir -- so we never rm the overlay/sockets out from
# under a still-running QEMU.
cogbox_cleanup() {
	# Capture the status that triggered the EXIT trap BEFORE any command below
	# overwrites $? -- it tells us whether the start succeeded.
	local rc=$?
	[ "$CLEANED" -eq 1 ] && return
	CLEANED=1
	if [ -n "$QEMU_PID" ]; then
		kill -TERM "$QEMU_PID" 2>/dev/null
		for _ in $(seq 1 50); do
			kill -0 "$QEMU_PID" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$QEMU_PID" 2>/dev/null
		wait "$QEMU_PID" 2>/dev/null
	fi
	[ -n "$PASST_PID" ] && kill "$PASST_PID" 2>/dev/null
	[ -n "$L7PROXY_PID" ] && kill "$L7PROXY_PID" 2>/dev/null
	[ -n "$L7MITM_PID" ] && kill "$L7MITM_PID" 2>/dev/null
	# Remove this instance's sanitized cred-inject mirrors (QEMU is dead now, so
	# the 9p source is no longer in use). The mirror is hardlinks/no secret, but
	# tidy it rather than leave it under the data root until the next boot.
	rm -rf "$BASE_DATA/mirrors/${EFFECTIVE_NAME}"
	rmdir "$BASE_DATA/mirrors" 2>/dev/null
	# Remove the transient runtime dir only on a CLEAN exit: a deliberate stop
	# (143, from the TERM/INT trap below) or a clean QEMU shutdown (0). On any
	# other status the start FAILED -- a die() before the VM came up, or QEMU
	# dying during boot -- so keep $RUNTIME (and its cogbox.log) intact: that is
	# the very file `cogbox start` tells the user to read ("VM did not come up.
	# See .../cogbox.log"), and blowing it away here left them with a dangling
	# pointer. A stale dir is harmless -- the next start removes it (its pid is
	# dead) before recreating, so failed-start logs never accumulate.
	if [ "$rc" -eq 0 ] || [ "$rc" -eq 143 ]; then
		rm -rf "$RUNTIME"
	elif [ -n "$QEMU_PID" ]; then
		# QEMU had launched, so the start itself succeeded -- this is the VM
		# dying later (a crash, an external SIGKILL, a guest fault). Keep the
		# dir: cogbox.log/console.log are the post-mortem for that exit.
		echo "cogbox-launch: VM terminated unexpectedly (status $rc); keeping runtime dir for diagnosis: $RUNTIME/cogbox.log" >&2
	else
		# Failed before QEMU ever launched (passt/L7/persist) -- the "VM did not
		# come up" case; keep the log the start error points the user at.
		echo "cogbox-launch: start failed (status $rc); keeping runtime dir for diagnosis: $RUNTIME/cogbox.log" >&2
	fi
	# Leave $LOCK in place: it is an flock target, not a pid file. Our held
	# fd is released when this process exits (kernel-managed); unlinking it
	# here would only risk a new starter racing on a fresh inode. The empty
	# file lingers harmlessly in the tmpfs runtime base (cleared on logout).
}
trap cogbox_cleanup EXIT
# SIGTERM/SIGINT -> exit -> EXIT trap fires cogbox_cleanup. Interrupts the
# `wait "$QEMU_PID"` at the end of the script.
trap 'exit 143' TERM INT

ln -sfn "$REAL_DATA" "$RUNTIME/data"

# -- Per-harness runtime sources -----------------------------------
# The QEMU runner expects a 9p source path or fw_cfg file at
# $RUNTIME/<harness>-<pathkey> for every overlay/fw_cfg path declared
# in the harness shape. For active harnesses, we symlink to the host
# state. For inactive harnesses, we materialize an empty stub so the
# QEMU runner doesn't fail to start.
HARNESS_STUBS="$RUNTIME/.harness-stubs"
mkdir -p "$HARNESS_STUBS"
# Is host-side credential injection active for this instance? If so, secret
# files are evicted from the guest overlays below (stage_overlay_source).
INJECT_ACTIVE=0
# Accept both the legacy bool (.network.l7.inject == true) and the object form
# (.network.l7.inject.enabled == true). The object form is written by the Zig
# verbs (e.g. `cogbox plugin add` merging inject specs); the bool form keeps
# working for instances inited before it. Gates harness cred eviction +
# harness inject-conf generation; plugin/operator specs render independently.
if [ "$NETWORK_MODE" = "rules" ] \
	&& jq -e '(.network.l7.inject == true) or (.network.l7.inject.enabled == true)' "$ACTIVE_CONFIG" >/dev/null 2>&1; then
	INJECT_ACTIVE=1
fi
is_active() {
	for active in "${ACTIVE_HARNESSES[@]}"; do
		[ "$active" = "$1" ] && return 0
	done
	return 1
}
for h in "${HARNESSES[@]}"; do
	while IFS= read -r k; do
		[ -z "$k" ] && continue
		kind=${H_KIND[$h:$k]}
		[ "$kind" = "ephemeral" ] && continue
		target="$RUNTIME/${h}-${k}"
		if is_active "$h"; then
			host=${H_HOST[$h:$k]}
			if [ "$kind" = "overlay" ]; then
				host="$(stage_overlay_source "$h" "$k" "$host")"
			fi
			ln -sfn "$host" "$target"
		else
			stub="$HARNESS_STUBS/${h}-${k}"
			case "$kind" in
				overlay)
					mkdir -p "$stub"
					;;
				fw_cfg)
					if [ ! -e "$stub" ]; then
						printf '%s' "${H_FW_DEFAULT[$h:$k]}" > "$stub"
						chmod "${H_FW_MODE[$h:$k]}" "$stub"
					fi
					;;
			esac
			ln -sfn "$stub" "$target"
		fi
	done < <(harness_pathkeys "$h")
done

# -- Generate runtime rule files -----------------------------------
# Render BOTH the LD_PRELOAD filter's netfilter-rules (CIDR + remap +
# the auto-injected L7 funnel lines) and the L7 proxy's l7-rules from
# config.json, using the same Zig renderer the hot-reload path uses --
# so boot output and edit output can never drift.
# The fw_cfg CA device is ALWAYS present (the flake emits it unconditionally),
# so seed an empty stub; rules mode overwrites it with the real cert.
: > "$RUNTIME/system-l7ca"
if [ "$NETWORK_MODE" = "rules" ]; then
	@cogbox@ __render-rules "$ACTIVE_CONFIG" "$RUNTIME"
	# Host-side credential injection. __render-rules already wrote the
	# PLUGIN/OPERATOR inject specs (resolved from the secret store, audience-
	# gated) to l7-inject-conf.json. Merge the HARNESS specs (cred-file +
	# OAuth-refresh, gated on the harness opt-in INJECT_ACTIVE) on top into the
	# single conf start_l7mitm reads -- harness specs win a host collision.
	# Plugin specs render independently of INJECT_ACTIVE (their own bound state
	# gates them). An explicit COGBOX_L7_INJECT_CONF overrides the whole thing.
	if [ -z "${COGBOX_L7_INJECT_CONF:-}" ]; then
		_plugin_conf=$(cat "$RUNTIME/l7-inject-conf.json" 2>/dev/null)
		[ -z "$_plugin_conf" ] && _plugin_conf='[]'
		_harness_conf='[]'
		if [ "$INJECT_ACTIVE" = 1 ]; then
			_harness_conf=$(gen_inject_conf)
			[ -z "$_harness_conf" ] && _harness_conf='[]'
		fi
		# jq -s slurps both arrays; `add` concatenates (plugin first, harness
		# last -> harness wins the addon's last-write-by-host).
		if printf '%s\n%s' "$_plugin_conf" "$_harness_conf" \
			| jq -s 'add' > "$RUNTIME/l7-inject-conf.json.tmp" 2>/dev/null; then
			mv "$RUNTIME/l7-inject-conf.json.tmp" "$RUNTIME/l7-inject-conf.json"
		else
			rm -f "$RUNTIME/l7-inject-conf.json.tmp"
		fi
		# l7-inject-hosts (the L7 proxy's plain-HTTP inject-routing list) was
		# already written by __render-rules from the PLUGIN/OPERATOR specs only.
		# We deliberately do NOT add the HARNESS hosts to it: their providers are
		# HTTPS-only, and routing their plain-HTTP egress through the injector
		# would let the guest force a cleartext send of the real OAuth token.
	else
		# Operator override: the addon reads exactly $COGBOX_L7_INJECT_CONF, so
		# the proxy's HTTP inject-routing list must mirror ITS hosts (replacing
		# the config-rendered plugin set __render-rules just wrote). Capture jq
		# on its OWN (no pipe) so its exit status is observed: a malformed or
		# unreadable conf (jq non-zero) fails CLOSED to an empty list -- no
		# routing, never a wrong one. (Piping jq into sort would mask the failure
		# behind sort's always-zero exit.)
		if _override_hosts=$(jq -r '.[].host // empty' "$COGBOX_L7_INJECT_CONF" 2>/dev/null); then
			printf '%s\n' "$_override_hosts" | sort -u > "$RUNTIME/l7-inject-hosts"
		else
			: > "$RUNTIME/l7-inject-hosts"
		fi
	fi
fi

# -- Patch the microvm runner with runtime QEMU settings -----------
PASST_SOCK="$RUNTIME/passt.sock"
SED_ARGS=(
	-e "s/( )-smp [0-9]+/\1-smp $VCPU/"
	-e "s/( )-m [0-9]+/\1-m $MEM/"
	-e "s/(memory-backend-memfd,id=mem,size=)[0-9]+(M)/\1${MEM}\2/"
	-e "s|${RUNTIME_TEMPLATE}/|${RUNTIME}/|g"
	-e "s|@cogbox-instance@|${EFFECTIVE_NAME}|g"
	# Move the guest serial console off QEMU's stdio onto a persistent unix
	# socket so it can be attached/detached at will (cogbox console) while
	# the VM runs in the background. Keeping id=stdio means microvm's
	# `-serial chardev:stdio` keeps resolving. logfile= captures the full
	# session's serial output for replay on attach. The replacement targets
	# only the chardev descriptor, so it is agnostic to how microvm quotes
	# the arg. The runtime dir is recreated per launch, so no logappend.
	-e "s|stdio,id=stdio,signal=off|socket,id=stdio,path=${RUNTIME}/console.sock,server=on,wait=off,logfile=${RUNTIME}/console.log|"
)
if [ "$NETWORK_MODE" = "none" ]; then
	# SLIRP with restrict=on -- blocks all outbound, keeps port forwards
	SED_ARGS+=(
		-e "s/hostfwd=tcp:[^-]*-:22/hostfwd=tcp:$BIND_ADDR:$SSH_PORT-:22/g"
		-e "s/hostfwd=tcp:[^-]*-:8080/hostfwd=tcp:$BIND_ADDR:$HTTP_PORT-:8080/g"
		-e "s/(user,id=usernet)/\1,restrict=on/"
	)
else
	# full and rules: connect to passt via unix socket (launched separately)
	SED_ARGS+=(-e "s|-netdev '[^']*'|-netdev 'stream,id=usernet,server=off,addr.type=unix,addr.path=${PASST_SOCK}'|")
fi

sed -E "${SED_ARGS[@]}" "$RUNNER_DIR/bin/microvm-run" > "$RUNTIME/run"
chmod +x "$RUNTIME/run"

# Fail loud if the serial-console rewrite did not take (e.g. microvm changed
# the chardev string): otherwise the console would silently fall back to
# stdio (the daemon log) and `cogbox console` would find no socket.
if ! grep -q "console.sock" "$RUNTIME/run"; then
	echo "cogbox-launch: warning: serial console socket rewrite did not apply; 'cogbox console' will not work for this instance." >&2
fi

# -- Launch --------------------------------------------------------
if [ "$NETWORK_MODE" = "none" ]; then
	echo "Warning: network mode is \"none\" -- all outbound traffic is blocked."
	echo "Harnesses that need outbound API access (claude-code, opencode) won't"
	echo "function unless you provide it via SSH tunnel or similar."
fi

# -- Helper: wait for passt socket ---------------------------------
wait_for_passt() {
	while [ ! -S "$PASST_SOCK" ] && kill -0 "$PASST_PID" 2>/dev/null; do
		sleep 0.1
	done
	if [ ! -S "$PASST_SOCK" ]; then
		die "passt failed to start." 70
	fi
}

# -- Helper: start the host-side L7 proxy --------------------------
# Runs WITHOUT the LD_PRELOAD shim (so it reaches the internet directly to
# re-resolve allowed vhosts) and writes its pid for the hot-reload SIGHUP
# path. Started for EVERY rules-mode instance (it is a cheap, idle loopback
# listener until the funnel diverts to it), so that enabling L7 on an
# already-running instance via `cogbox l7 add` works without a restart -- the
# funnel hot-reloads into passt and the proxy is already listening. Failure to
# bind is FATAL: we abort the start (per-instance ports mean a bind failure is a
# real conflict, not a benign race), so the instance never boots with a funnel
# that can't reach its proxy.
start_l7proxy() {
	@cogbox@ __l7proxy "$RUNTIME" "$L7_BASE" &
	L7PROXY_PID=$!
	echo "$L7PROXY_PID" > "$RUNTIME/l7proxy.pid"
	# Brief liveness check, then FAIL CLOSED. The proxy binds this instance's
	# per-instance loopback ports ($L7_BASE / +1); if it can't (a stale proxy
	# or another process holds them) we abort the start rather than boot a VM
	# whose L7 funnel points at a dead/foreign port. die() trips the cleanup
	# trap, tearing down passt/mitmproxy/QEMU.
	sleep 0.2
	if ! kill -0 "$L7PROXY_PID" 2>/dev/null; then
		L7PROXY_PID=""
		die "L7 proxy failed to bind 127.0.0.1:${L7_BASE}/$(( L7_BASE + 1 )) -- is a stale proxy or another process holding those ports? Aborting start." 75
	fi
}

# -- Helper: start the L7 terminate backend (mitmproxy) ------------
# Runs mitmdump in SOCKS5 mode with a PERSISTENT per-instance CA confdir (so
# the guest-trusted cert survives reboots) and our enforcement addon. The Zig
# proxy hands vetted terminate-host connections here. After the CA materializes
# we stage its CERT (never the key) into the fw_cfg slot for guest injection.
start_l7mitm() {
	local ca_dir="$INSTANCE_CONFIG_DIR/l7-ca"
	mkdir -p "$ca_dir"
	# connection_strategy=lazy: defer the upstream connection until AFTER the
	# addon has decided, so a denied request never opens a connection to the
	# upstream (and a deny to an unreachable upstream still returns 403 rather
	# than dropping the client's TLS handshake).
	#
	# Host-side credential injection: when an inject-conf is present, the addon
	# replaces a harness's request auth header with the real token read off the
	# host FS (mitmdump runs host-side as the launching user), so the guest only
	# ever carries a stub and the long-lived token never enters the sandbox. The
	# conf maps host -> {cred_file, token_path, style} and lives host-side only.
	# Resolution: an explicit COGBOX_L7_INJECT_CONF wins; otherwise a launch-time
	# step may drop the conf at the runtime default below. A missing file blanks
	# the var so the addon falls back to legacy "guest carries its own token".
	local inject_conf="${COGBOX_L7_INJECT_CONF:-$RUNTIME/l7-inject-conf.json}"
	[ -f "$inject_conf" ] || inject_conf=""
	COGBOX_L7_RULES="$RUNTIME/l7-rules" \
	COGBOX_L7_INJECT_CONF="$inject_conf" \
	@mitmdump@ --mode "socks5@${L7_MITM_PORT}" --listen-host 127.0.0.1 \
		--set confdir="$ca_dir" --set http2=false --set connection_strategy=lazy \
		-s "@l7addon@" -q &
	L7MITM_PID=$!
	echo "$L7MITM_PID" > "$RUNTIME/l7mitm.pid"
	# Wait for mitmproxy to generate its CA (first run) or confirm it exists.
	for _ in $(seq 1 100); do
		[ -s "$ca_dir/mitmproxy-ca-cert.pem" ] && break
		kill -0 "$L7MITM_PID" 2>/dev/null || break
		sleep 0.1
	done
	if ! kill -0 "$L7MITM_PID" 2>/dev/null || [ ! -s "$ca_dir/mitmproxy-ca-cert.pem" ]; then
		echo "cogbox-launch: warning: L7 terminate backend failed to start; terminate hosts will be blocked." >&2
		L7MITM_PID=""
		return
	fi
	# Stage the CA CERT (cert only) for fw_cfg. Guard against ever leaking the
	# private key into the guest.
	if grep -q "PRIVATE KEY" "$ca_dir/mitmproxy-ca-cert.pem"; then
		die "refusing to stage L7 CA: mitmproxy-ca-cert.pem contains a private key" 70
	fi
	cp "$ca_dir/mitmproxy-ca-cert.pem" "$RUNTIME/system-l7ca"
}

# Launch QEMU as a background child and wait for it. Backgrounding (rather
# than a bare foreground exec) is what lets the TERM/INT traps above signal
# QEMU so `cogbox stop` shuts the VM down cleanly.
launch_vm() {
	cd "$RUNTIME" || die "cannot enter runtime dir $RUNTIME" 70
	"$RUNTIME/run" &
	QEMU_PID=$!
	# Readiness/liveness marker the parent (`cogbox start`) waits on. Written
	# the instant QEMU is launched, regardless of whether the serial console
	# rewrite applied, so a console-less VM (e.g. a flake that disables
	# serialConsole) is still detected as up rather than timing out.
	echo "$QEMU_PID" > "$RUNTIME/qemu.pid"
	wait "$QEMU_PID"
}

if [ "$NETWORK_MODE" = "rules" ]; then
	# Rules mode: passt with LD_PRELOAD netfilter
	NETFILTER_RULES="$RUNTIME/netfilter-rules" \
	LD_PRELOAD="@netfilter@" \
	passt --foreground --socket "$PASST_SOCK" \
		-t "$SSH_PORT:22" -t "$HTTP_PORT:8080" &
	PASST_PID=$!
	echo "$PASST_PID" > "$RUNTIME/passt.pid"
	wait_for_passt
	# Start the terminate backend first so its CA is staged into the fw_cfg
	# slot BEFORE QEMU reads fw_cfg at launch. It runs for EVERY rules-mode
	# instance, not just those with L7 rules at boot: rules are hot-addable
	# (`cogbox l7 add` on a live instance), terminate is the default tier,
	# and the CA can only enter the guest trust store at launch -- so gating
	# this on boot-time rule presence broke the first hot-added rule (the
	# proxy handed TLS to a backend that was never started and failed
	# closed). An idle backend on L4-only instances is the accepted cost.
	start_l7mitm
	# Always run the L7 proxy in rules mode so L7 can be enabled on a live
	# instance without a restart (the funnel only diverts to it once a rule
	# exists; until then it idles).
	start_l7proxy
	launch_vm
elif [ "$NETWORK_MODE" != "none" ]; then
	# Full mode: unrestricted passt
	passt --foreground --socket "$PASST_SOCK" \
		-t "$SSH_PORT:22" -t "$HTTP_PORT:8080" &
	PASST_PID=$!
	echo "$PASST_PID" > "$RUNTIME/passt.pid"
	wait_for_passt
	launch_vm
else
	launch_vm
fi
