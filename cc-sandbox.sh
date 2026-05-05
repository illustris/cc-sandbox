ORIG_ARGS=("$@")

# Scaffold written into each instance's config dir on first init. Also used
# by the re-exec check below: if the user hasn't edited flake.nix, the
# resulting microvm closure is identical to the baked-in default and we can
# skip the (network-dependent) `nix run` re-eval entirely.
# shellcheck disable=SC2016
SCAFFOLD_FLAKE='{
	description = "cc-sandbox per-instance extensions";

	# `pkgs` in nixosModules.default below comes from cc-sandbox'\''s nixpkgs.
	# To use a different nixpkgs, add an input here (e.g.
	# inputs.nixpkgs-custom.url = "...";) and reference it explicitly.
	# cc-sandbox always overrides any "nixpkgs" input you declare to its
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

usage() {
	cat <<'EOF'
Usage: cc-sandbox [OPTIONS]
       cc-sandbox rules COMMAND [--name NAME]
       cc-sandbox ssh [--name NAME] [REMOTE_COMMAND...]

Run coding-agent harnesses (Claude Code, opencode) in an isolated QEMU microvm.

Options:
  --name NAME      Use a named instance (creates it on first run)
  --vcpu N         Set vCPU count (default: config or 16)
  --mem N          Set RAM in megabytes (default: config or 32768)
  --network MODE   Network mode: full, none, or rules (default: config or rules)
  --init-only      Run all setup steps but do not start the VM
  --list           List all instances with their ports and status
  --no-auto-keys   On first init, leave authorized_keys empty instead of
                   seeding it from ~/.ssh/*.pub and ssh-add -L.
  --help           Show this help message

Per-instance customization:
  Each instance has a flake.nix at ~/.config/cc-sandbox/instances/<name>/flake/.
  Edit it to add packages or NixOS modules; the next launch rebuilds the
  microvm with your changes. cc-sandbox always overrides the user flake's
  "nixpkgs" input to its own; declare a separate input (e.g. "nixpkgs-custom")
  for a different nixpkgs.

Network modes:
  "full"           Unrestricted networking
  "none"           Block all outbound traffic (QEMU restrict=on)
  "rules"          Ordered CIDR allow/deny rules (LD_PRELOAD filter on passt).
                   Default. Seeded with denies for private (RFC1918), link-local
                   (incl. cloud metadata 169.254.169.254), and bogon ranges,
                   followed by allow 0.0.0.0/0 for the public internet.

Rules subcommands:
  rules list                          List current rules with indices
  rules add allow|deny CIDR [--at N]  Add a rule (append, or insert at position N)
  rules del INDEX                     Delete a rule by index (1-based)
  rules set                           Replace all rules from stdin

Ssh subcommand:
  ssh [--name NAME] [REMOTE_COMMAND...]
                   Connect to the running instance over SSH. Resolves the
                   live port/host from the runtime directory, so it works
                   without remembering auto-assigned ports. Disables host
                   key checking since the guest's root disk is ephemeral.

Paths (XDG basedir spec):
  Config:  $XDG_CONFIG_HOME/cc-sandbox        (default: ~/.config/cc-sandbox)
  Data:    $XDG_DATA_HOME/cc-sandbox          (default: ~/.local/share/cc-sandbox)
  Runtime: $XDG_RUNTIME_DIR/cc-sandbox        (default: /run/user/$UID/cc-sandbox)

Environment variables:
  CC_SANDBOX_DATA              Override the data root. Each instance lives at
                               $CC_SANDBOX_DATA/instances/<name>; the default
                               instance uses the reserved name "default".
  CC_SANDBOX_CLAUDE_CONFIG     Host claude-code config dir (default: ~/.claude)
  CC_SANDBOX_CLAUDE_AUTH       claude-code auth token file
                               (default: ~/.claude.json)
  CC_SANDBOX_OPENCODE_CONFIG   Host opencode config dir
                               (default: $XDG_CONFIG_HOME/opencode)
  CC_SANDBOX_OPENCODE_DATA     Host opencode data dir, includes auth.json
                               (default: $XDG_DATA_HOME/opencode)

Examples:
  cc-sandbox                          Start the default instance
  cc-sandbox --name work              Start a named instance
  cc-sandbox --name work --vcpu 8     Named instance with 8 cores
  cc-sandbox --network none           Start fully isolated
  cc-sandbox --network full           Override default rules mode for unrestricted net
  cc-sandbox rules add allow 10.0.0.0/8 --name work
  cc-sandbox rules list --name work
  cc-sandbox ssh                      SSH into the default instance
  cc-sandbox ssh --name work htop     Run htop on the "work" instance
  cc-sandbox --list                   Show all instances
  cc-sandbox --init-only              Set up without booting
EOF
	exit 0
}

INIT_ONLY=0
FLAG_VCPU=""
FLAG_MEM=""
FLAG_NETWORK=""
INSTANCE_NAME=""
LIST_INSTANCES=0
RULES_MODE=0
RULES_ARGS=()
SSH_MODE=0
SSH_ARGS=()
AUTO_KEYS=1
while [ $# -gt 0 ]; do
	case "$1" in
		--init-only) INIT_ONLY=1 ;;
		--vcpu|--mem|--network|--name)
			if [ $# -lt 2 ]; then
				echo "Error: $1 requires a value."
				exit 1
			fi
			;;&
		--vcpu) FLAG_VCPU="$2"; shift ;;
		--mem) FLAG_MEM="$2"; shift ;;
		--network) FLAG_NETWORK="$2"; shift ;;
		--name) INSTANCE_NAME="$2"; shift ;;
		--list) LIST_INSTANCES=1 ;;
		--no-auto-keys) AUTO_KEYS=0 ;;
		--help) usage ;;
		rules)
			RULES_MODE=1
			shift
			# Capture remaining args verbatim for cc-sandbox-rules. Pull
			# --name <NAME> out so the shell can resolve the instance dir;
			# everything else passes through to the Zig binary.
			while [ $# -gt 0 ]; do
				case "$1" in
					--name)
						if [ $# -lt 2 ]; then
							echo "Error: --name requires a value."
							exit 1
						fi
						INSTANCE_NAME="$2"; shift 2
						;;
					*)
						RULES_ARGS+=("$1"); shift
						;;
				esac
			done
			break
			;;
		ssh)
			SSH_MODE=1
			shift
			# Capture remaining args verbatim as the ssh remote command.
			# Pull --name <NAME> out so the shell can resolve the runtime
			# dir; everything else is appended to the ssh invocation.
			while [ $# -gt 0 ]; do
				case "$1" in
					--name)
						if [ $# -lt 2 ]; then
							echo "Error: --name requires a value."
							exit 1
						fi
						INSTANCE_NAME="$2"; shift 2
						;;
					*)
						SSH_ARGS+=("$1"); shift
						;;
				esac
			done
			break
			;;
	esac
	shift
done

# -- Validate instance name ---------------------------------------
if [ -n "$INSTANCE_NAME" ]; then
	if ! printf '%s' "$INSTANCE_NAME" | grep -qE '^[a-zA-Z][a-zA-Z0-9-]{0,63}$'; then
		echo "Error: instance name must start with a letter, contain only"
		echo "alphanumeric characters and hyphens, and be at most 64 characters."
		exit 1
	fi
	if [ "$INSTANCE_NAME" = "default" ]; then
		echo "Error: 'default' is reserved. Omit --name to use the default instance."
		exit 1
	fi
fi

# -- Validate --network CLI value ---------------------------------
if [ -n "$FLAG_NETWORK" ] && [ "$FLAG_NETWORK" != "full" ] && [ "$FLAG_NETWORK" != "none" ] && [ "$FLAG_NETWORK" != "rules" ]; then
	echo "Error: --network must be \"full\", \"none\", or \"rules\"."
	exit 1
fi

# -- Resolve real user for sudo context ----------------------------
if [ -n "${SUDO_USER:-}" ]; then
	REAL_USER="$SUDO_USER"
	REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	REAL_UID=$(getent passwd "$SUDO_USER" | cut -d: -f3)
else
	REAL_USER="$(id -un)"
	REAL_HOME="$HOME"
	REAL_UID="$(id -u)"
fi

# -- Paths (XDG basedir spec) --------------------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$REAL_HOME/.config}/cc-sandbox"
BASE_DATA="${CC_SANDBOX_DATA:-${XDG_DATA_HOME:-$REAL_HOME/.local/share}/cc-sandbox}"

# -- Harness shape -------------------------------------------------
# Mirror of the harness attrset in flake.nix. Both sides must agree on
# names (used as 9p tags, fw_cfg keys, and runtime symlinks). When
# adding or changing a harness, edit BOTH this section and the
# `mkHarnesses` attrset in flake.nix.
#
# Path kinds:
#   overlay   - 9p RO lowerdir from host + persistent upperdir in the
#               shared harness overlay image. Host path must exist.
#   fw_cfg    - single host file copied into the guest at boot via
#               QEMU's fw_cfg device. Host path must exist (a stub
#               with default content is created if absent).
#   ephemeral - sandbox-only; bind-mounted from the harness overlay
#               image. No host source.
HARNESSES=(claude-code opencode)
declare -A H_KIND
declare -A H_HOST
declare -A H_FW_DEFAULT
declare -A H_FW_MODE

H_KIND[claude-code:config]=overlay
H_HOST[claude-code:config]="${CC_SANDBOX_CLAUDE_CONFIG:-$REAL_HOME/.claude}"

H_KIND[claude-code:auth]=fw_cfg
H_HOST[claude-code:auth]="${CC_SANDBOX_CLAUDE_AUTH:-$REAL_HOME/.claude.json}"
H_FW_DEFAULT[claude-code:auth]='{}'
H_FW_MODE[claude-code:auth]=600

H_KIND[opencode:config]=overlay
H_HOST[opencode:config]="${CC_SANDBOX_OPENCODE_CONFIG:-${XDG_CONFIG_HOME:-$REAL_HOME/.config}/opencode}"

H_KIND[opencode:data]=overlay
H_HOST[opencode:data]="${CC_SANDBOX_OPENCODE_DATA:-${XDG_DATA_HOME:-$REAL_HOME/.local/share}/opencode}"

H_KIND[opencode:cache]=ephemeral
H_KIND[opencode:state]=ephemeral

# Path keys per harness, in declared order.
harness_pathkeys() {
	case "$1" in
		claude-code) printf '%s\n' config auth ;;
		opencode) printf '%s\n' config data cache state ;;
	esac
}

# Human-readable summary of what creating a harness's host state will
# do, used in the "set up which?" prompt.
harness_summary() {
	case "$1" in
		claude-code) echo "creates ~/.claude/, ~/.claude.json" ;;
		opencode)    echo "creates ~/.config/opencode/, ~/.local/share/opencode/" ;;
	esac
}

# Microvm runner has runtime paths baked in at flake build time using this
# sentinel; the sed substitution below rewrites them to BASE_RUNTIME.
RUNTIME_TEMPLATE="@runtimeDir@"

# Per-user runtime dir per the XDG basedir spec. Under sudo, XDG_RUNTIME_DIR
# typically points at root's tree (or is unset); use the invoking user's
# /run/user/$UID instead. If that doesn't exist (no active logind session),
# fall back to /tmp/cc-sandbox-runtime-$UID per the spec's "replacement
# directory with similar capabilities" guidance.
if [ -n "${SUDO_USER:-}" ] || [ -z "${XDG_RUNTIME_DIR:-}" ]; then
	XDG_RUNTIME_BASE="/run/user/$REAL_UID"
else
	XDG_RUNTIME_BASE="$XDG_RUNTIME_DIR"
fi
if [ ! -d "$XDG_RUNTIME_BASE" ]; then
	XDG_RUNTIME_BASE="/tmp/cc-sandbox-runtime-$REAL_UID"
	mkdir -p "$XDG_RUNTIME_BASE"
	chmod 700 "$XDG_RUNTIME_BASE"
fi
BASE_RUNTIME="$XDG_RUNTIME_BASE/cc-sandbox"

EFFECTIVE_NAME="${INSTANCE_NAME:-default}"
INSTANCE_CONFIG_DIR="$CONFIG_DIR/instances/$EFFECTIVE_NAME"
# The flake lives in its own subdir so unrelated edits to config.json /
# authorized_keys don't bust the userExtensions flake's source hash.
INSTANCE_FLAKE_DIR="$INSTANCE_CONFIG_DIR/flake"
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
		echo "Error: cc-sandbox layout changed. The default instance now lives at:"
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
		exit 1
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
		echo "Error: cc-sandbox flake layout changed. The per-instance flake now lives at:"
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
		exit 1
	fi
fi

# Multi-harness migration: rename the per-instance overlay image from
# the old single-harness name. The image's content is preserved
# verbatim; the in-image upper/work shuffle into claude-code/config/
# is handled by harness-setup-dirs.service inside the guest.
if [ -d "$REAL_DATA" ] && [ -f "$REAL_DATA/claude-overlay.img" ] && [ ! -f "$REAL_DATA/harness-overlay.img" ]; then
	mv "$REAL_DATA/claude-overlay.img" "$REAL_DATA/harness-overlay.img"
fi

# -- List instances ------------------------------------------------
if [ "$LIST_INSTANCES" -eq 1 ]; then
	net_label() {
		local raw
		raw=$(jq -c '.network // "full"' "$1")
		if [ "$raw" = '"full"' ] || [ "$raw" = '"none"' ]; then
			echo "$raw" | tr -d '"'
		else
			echo "rules"
		fi
	}
	echo "Instances:"
	if [ -d "$CONFIG_DIR/instances" ]; then
		for dir in "$CONFIG_DIR/instances"/*/; do
			[ -d "$dir" ] || continue
			name=$(basename "$dir")
			cfg="$dir/config.json"
			[ -f "$cfg" ] || continue
			ssh_p=$(jq -r '.sshPort // 2222' "$cfg")
			http_p=$(jq -r '.httpPort // 8080' "$cfg")
			net=$(net_label "$cfg")
			running=""
			if [ "$name" = "default" ]; then
				inst_runtime="$BASE_RUNTIME"
				label="(default)"
			else
				inst_runtime="${BASE_RUNTIME}-${name}"
				label="$name"
			fi
			if [ -f "$inst_runtime/pid" ] && kill -0 "$(cat "$inst_runtime/pid")" 2>/dev/null; then
				running=" (running)"
			fi
			echo "  $label  ssh:$ssh_p  http:$http_p  net:$net$running"
		done
	fi
	exit 0
fi

# -- Rules subcommand ----------------------------------------------
if [ "$RULES_MODE" -eq 1 ]; then
	ACTIVE_CONFIG="$INSTANCE_CONFIG_DIR/config.json"
	if [ ! -f "$ACTIVE_CONFIG" ]; then
		echo "Error: no config found at $ACTIVE_CONFIG"
		exit 1
	fi
	exec @rules@ \
		--config "$ACTIVE_CONFIG" \
		--runtime "$RUNTIME" \
		"${RULES_ARGS[@]}"
fi

# -- SSH subcommand ------------------------------------------------
# Read the live port/host from the runtime dir written by the launch
# path below. Reading config.json instead would risk connecting on a
# stale port if the user edited it after boot. The VM's root disk is
# ephemeral, so its host keys regenerate on every reboot -- pin
# UserKnownHostsFile=/dev/null and disable strict checking to skip the
# spurious MITM warning. LogLevel=ERROR suppresses the "Permanently
# added ..." chatter that would otherwise accompany every connection.
if [ "$SSH_MODE" -eq 1 ]; then
	if [ ! -f "$RUNTIME/pid" ] || ! kill -0 "$(cat "$RUNTIME/pid")" 2>/dev/null; then
		echo "Error: instance${INSTANCE_NAME:+ \"$INSTANCE_NAME\"} is not running."
		echo "Start it first with: cc-sandbox${INSTANCE_NAME:+ --name $INSTANCE_NAME}"
		exit 1
	fi
	if [ ! -f "$RUNTIME/ssh-endpoint" ]; then
		echo "Error: missing $RUNTIME/ssh-endpoint (instance launched by an older cc-sandbox?)."
		echo "Restart the instance to repopulate it."
		exit 1
	fi
	read -r SSH_PORT BIND_ADDR < "$RUNTIME/ssh-endpoint"
	exec ssh \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR \
		-p "$SSH_PORT" \
		"root@$BIND_ADDR" \
		"${SSH_ARGS[@]}"
fi

# -- Auto-port assignment -----------------------------------------
next_available_ports() {
	# Seeded one below the default's canonical 2222/8080, so the first
	# named instance auto-assigns to 2223/8081 even if the default does
	# not yet exist (i.e. 2222/8080 stays reserved for the default).
	local max_ssh=2222
	local max_http=8080

	if [ -d "$CONFIG_DIR/instances" ]; then
		for cfg in "$CONFIG_DIR/instances"/*/config.json; do
			[ -f "$cfg" ] || continue
			local s h
			s=$(jq -r '.sshPort // 0' "$cfg")
			h=$(jq -r '.httpPort // 0' "$cfg")
			[ "$s" -gt "$max_ssh" ] && max_ssh=$s
			[ "$h" -gt "$max_http" ] && max_http=$h
		done
	fi

	echo "$(( max_ssh + 1 )) $(( max_http + 1 ))"
}

# -- Harness state detection (D3) ----------------------------------
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
if [ ! -d "$REAL_DATA" ]; then
	ITEMS+=("$REAL_DATA/  (VM data${INSTANCE_NAME:+ for \"$INSTANCE_NAME\"})")
fi

# If no harness has host state yet, prompt the user to pick which to
# set up. This avoids polluting $HOME with config dirs for tools the
# user doesn't use (D3). Under a non-interactive stdin we can't safely
# prompt, so default to all harnesses.
if [ "${#ACTIVE_HARNESSES[@]}" -eq 0 ]; then
	if [ -t 0 ]; then
		echo "No harness state detected. Set up which?"
		idx=1
		for h in "${HARNESSES[@]}"; do
			echo "  [$idx] $h     ($(harness_summary "$h"))"
			idx=$((idx + 1))
		done
		echo "  [$idx] both"
		read -rp "Choice [1-$idx]: " choice
		case "$choice" in
			1) ACTIVE_HARNESSES=("${HARNESSES[0]}") ;;
			2) ACTIVE_HARNESSES=("${HARNESSES[1]}") ;;
			3) ACTIVE_HARNESSES=("${HARNESSES[@]}") ;;
			*) echo "Invalid choice."; exit 1 ;;
		esac
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
	read -rp "Continue? [y/N] " confirm
	if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
		echo "Aborted."
		exit 1
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
		NETWORK_JQ=$(jq -nc '{
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
		}')
	else
		NETWORK_JQ="\"$INIT_NETWORK\""
	fi

	if [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
		if [ -z "$INSTANCE_NAME" ]; then
			INIT_SSH=2222
			INIT_HTTP=8080
		else
			read -r INIT_SSH INIT_HTTP <<< "$(next_available_ports)"
		fi
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--argjson network "$NETWORK_JQ" \
			--argjson ssh "$INIT_SSH" \
			--argjson http "$INIT_HTTP" \
			'{
				vcpu: $vcpu,
				mem: $mem,
				sshPort: $ssh,
				httpPort: $http,
				overlaySize: "128M",
				storeOverlaySize: "16G",
				bindAddr: "127.0.0.1",
				network: $network
			}' > "$INSTANCE_CONFIG_DIR/config.json"
		[ -n "$INSTANCE_NAME" ] && echo "Instance \"$INSTANCE_NAME\" ports: SSH=$INIT_SSH HTTP=$INIT_HTTP"
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

# -- Fix file ownership after init under sudo ----------------------
if [ -n "${SUDO_USER:-}" ]; then
	chown -R "$REAL_USER" "$CONFIG_DIR" "$REAL_DATA"
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

# -- Re-exec with per-instance flake overlaid ---------------------
# Each instance owns a flake.nix that exposes nixosModules.default.
# We re-evaluate cc-sandbox with that flake patched in via
# --override-input, so the rebuilt microvm runner includes the user's
# modules. CC_SANDBOX_REEXECED breaks the loop after the first hop.
# The user flake's "nixpkgs" input is forced to follow cc-sandbox's
# nixpkgs by default; users can declare a separate input
# (e.g. nixpkgs-custom) for an independent nixpkgs.
if [ -z "${CC_SANDBOX_REEXECED:-}" ] && [ -f "$INSTANCE_FLAKE_DIR/flake.nix" ]; then
	# Skip re-exec when the user hasn't edited flake.nix from the scaffold.
	# The scaffold's nixosModules.default is empty, so the microvm closure
	# would be identical to the baked-in one anyway -- and re-evaluating
	# the cc-sandbox flake requires its inputs to be fetchable, which a
	# fresh "nix profile install" or NixOS-systemPackages setup may not have
	# locally cached. Users who actually customize their flake.nix opt into
	# the re-eval (and need network on first launch to populate the cache).
	# `cmp` is byte-exact and avoids the trailing-newline trim that command
	# substitution does.
	if ! printf '%s' "$SCAFFOLD_FLAKE" | cmp -s - "$INSTANCE_FLAKE_DIR/flake.nix"; then
		exec env CC_SANDBOX_REEXECED=1 nix \
			--extra-experimental-features "nix-command flakes" \
			run "path:@flakeSource@" \
			--override-input userExtensions "path:$INSTANCE_FLAKE_DIR" \
			--override-input userExtensions/nixpkgs "path:@nixpkgsSource@" \
			-- "${ORIG_ARGS[@]}"
	fi
fi

# -- Validate and read runtime config -----------------------------
ACTIVE_CONFIG="$INSTANCE_CONFIG_DIR/config.json"
if ! jq empty "$ACTIVE_CONFIG" 2>/dev/null; then
	echo "Error: invalid JSON in $ACTIVE_CONFIG"
	exit 1
fi

VCPU="${FLAG_VCPU:-$(jq -r '.vcpu // 16' "$ACTIVE_CONFIG")}"
MEM="${FLAG_MEM:-$(jq -r '.mem // 32768' "$ACTIVE_CONFIG")}"
SSH_PORT=$(jq -r '.sshPort // 2222' "$ACTIVE_CONFIG")
HTTP_PORT=$(jq -r '.httpPort // 8080' "$ACTIVE_CONFIG")
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
if [ -n "$INSTANCE_NAME" ] && [ -f "$INSTANCE_CONFIG_DIR/authorized_keys" ]; then
	cp "$INSTANCE_CONFIG_DIR/authorized_keys" "$REAL_DATA/.config/authorized_keys"
else
	cp "$CONFIG_DIR/authorized_keys" "$REAL_DATA/.config/authorized_keys"
fi

# -- Set up runtime symlink directory for QEMU ---------------------
if [ -e "$RUNTIME" ]; then
	if [ -f "$RUNTIME/pid" ] && kill -0 "$(cat "$RUNTIME/pid")" 2>/dev/null; then
		echo "Instance${INSTANCE_NAME:+ \"$INSTANCE_NAME\"} is already running (PID $(cat "$RUNTIME/pid"))."
		exit 1
	fi
	rm -rf "$RUNTIME"
fi
mkdir -p "$RUNTIME"
echo "$$" > "$RUNTIME/pid"
# Snapshot the active SSH endpoint for the `ssh` subcommand to read.
# Bound to runtime, not config, so post-boot edits to config.json don't
# misdirect connections to a port the VM isn't listening on.
echo "$SSH_PORT $BIND_ADDR" > "$RUNTIME/ssh-endpoint"
PASST_PID=""
trap 'kill "$PASST_PID" 2>/dev/null || true; rm -rf "'"$RUNTIME"'"' EXIT

ln -sfn "$REAL_DATA" "$RUNTIME/data"

# -- Per-harness runtime sources -----------------------------------
# The QEMU runner expects a 9p source path or fw_cfg file at
# $RUNTIME/<harness>-<pathkey> for every overlay/fw_cfg path declared
# in the harness shape. For active harnesses, we symlink to the host
# state. For inactive harnesses, we materialize an empty stub so the
# QEMU runner doesn't fail to start (the binary is installed in the
# guest unconditionally per D4, but inactive harnesses just see empty
# config dirs / default-content auth files).
HARNESS_STUBS="$RUNTIME/.harness-stubs"
mkdir -p "$HARNESS_STUBS"
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

# -- Generate rules file for LD_PRELOAD filter ---------------------
if [ "$NETWORK_MODE" = "rules" ]; then
	jq -r '.network.rules[] |
		if .allow then "allow \(.allow)"
		elif .deny then "deny \(.deny)"
		else empty end' "$ACTIVE_CONFIG" > "$RUNTIME/netfilter-rules"
fi

# -- Patch the microvm runner with runtime QEMU settings -----------
PASST_SOCK="$RUNTIME/passt.sock"
SED_ARGS=(
	-e "s/( )-smp [0-9]+/\1-smp $VCPU/"
	-e "s/( )-m [0-9]+/\1-m $MEM/"
	-e "s/(memory-backend-memfd,id=mem,size=)[0-9]+(M)/\1${MEM}\2/"
	-e "s|${RUNTIME_TEMPLATE}/|${RUNTIME}/|g"
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

sed -E "${SED_ARGS[@]}" "@runner@/bin/microvm-run" > "$RUNTIME/run"
chmod +x "$RUNTIME/run"

if [ "$INIT_ONLY" -eq 1 ]; then
	echo "Init complete${INSTANCE_NAME:+ (instance \"$INSTANCE_NAME\")}. Runtime directory: $RUNTIME"
	exit 0
fi

# -- Launch --------------------------------------------------------
if [ "$NETWORK_MODE" = "none" ]; then
	echo "Warning: network mode is \"none\" -- all outbound traffic is blocked."
	echo "Claude Code requires API access via SSH tunnel or similar."
fi

# -- Helper: wait for passt socket ---------------------------------
wait_for_passt() {
	while [ ! -S "$PASST_SOCK" ] && kill -0 "$PASST_PID" 2>/dev/null; do
		sleep 0.1
	done
	if [ ! -S "$PASST_SOCK" ]; then
		echo "Error: passt failed to start."
		exit 1
	fi
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
	cd "$RUNTIME"
	"$RUNTIME/run"
elif [ "$NETWORK_MODE" != "none" ]; then
	# Full mode: unrestricted passt
	passt --foreground --socket "$PASST_SOCK" \
		-t "$SSH_PORT:22" -t "$HTTP_PORT:8080" &
	PASST_PID=$!
	echo "$PASST_PID" > "$RUNTIME/passt.pid"
	wait_for_passt
	cd "$RUNTIME"
	"$RUNTIME/run"
else
	cd "$RUNTIME"
	"$RUNTIME/run"
fi
