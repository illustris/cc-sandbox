usage() {
	cat <<'EOF'
Usage: cc-sandbox [OPTIONS]
       cc-sandbox rules COMMAND [--name NAME]

Run Claude Code in an isolated QEMU microvm.

Options:
  --name NAME      Use a named instance (creates it on first run)
  --vcpu N         Set vCPU count (default: config or 16)
  --mem N          Set RAM in megabytes (default: config or 32768)
  --network MODE   Network mode: full, none, or rules (default: config or rules)
  --init-only      Run all setup steps but do not start the VM
  --list           List all instances with their ports and status
  --help           Show this help message

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

Environment variables:
  CC_SANDBOX_DATA           Persistent data root (default: ~/.local/share/cc-sandbox).
                            Each instance lives at $CC_SANDBOX_DATA/instances/<name>;
                            the default instance uses the reserved name "default".
  CC_SANDBOX_CLAUDE_CONFIG  Host Claude config dir (default: ~/.claude)
  CC_SANDBOX_CLAUDE_AUTH    Auth token file (default: ~/.claude.json)

Examples:
  cc-sandbox                          Start the default instance
  cc-sandbox --name work              Start a named instance
  cc-sandbox --name work --vcpu 8     Named instance with 8 cores
  cc-sandbox --network none           Start fully isolated
  cc-sandbox --network full           Override default rules mode for unrestricted net
  cc-sandbox rules add allow 10.0.0.0/8 --name work
  cc-sandbox rules list --name work
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
else
	REAL_USER="$(id -un)"
	REAL_HOME="$HOME"
fi

# -- Paths ---------------------------------------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$REAL_HOME/.config}/cc-sandbox"
BASE_DATA="${CC_SANDBOX_DATA:-$REAL_HOME/.local/share/cc-sandbox}"
REAL_CLAUDE_CONFIG="${CC_SANDBOX_CLAUDE_CONFIG:-$REAL_HOME/.claude}"
REAL_CLAUDE_AUTH="${CC_SANDBOX_CLAUDE_AUTH:-$REAL_HOME/.claude.json}"
BASE_RUNTIME="@runtimeDir@"

EFFECTIVE_NAME="${INSTANCE_NAME:-default}"
INSTANCE_CONFIG_DIR="$CONFIG_DIR/instances/$EFFECTIVE_NAME"
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

# -- First-time init: collect missing items, prompt once -----------
ITEMS=()
if [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
	if [ -z "$INSTANCE_NAME" ]; then
		ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (default settings)")
	else
		ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (instance \"$INSTANCE_NAME\" settings)")
	fi
fi
if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
	ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, empty)")
fi
if [ ! -d "$REAL_DATA" ]; then
	ITEMS+=("$REAL_DATA/  (VM data${INSTANCE_NAME:+ for \"$INSTANCE_NAME\"})")
fi
if [ ! -d "$REAL_CLAUDE_CONFIG" ]; then
	ITEMS+=("$REAL_CLAUDE_CONFIG/  (Claude config)")
fi
if [ ! -f "$REAL_CLAUDE_AUTH" ]; then
	ITEMS+=("$REAL_CLAUDE_AUTH  (Claude auth)")
fi

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

	mkdir -p "$INSTANCE_CONFIG_DIR" "$REAL_DATA" "$REAL_CLAUDE_CONFIG"

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

	if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
		touch "$CONFIG_DIR/authorized_keys"
	fi
	if [ ! -f "$REAL_CLAUDE_AUTH" ]; then
		echo '{}' > "$REAL_CLAUDE_AUTH"
		chmod 600 "$REAL_CLAUDE_AUTH"
	fi
fi

# -- Fix file ownership after init under sudo ----------------------
if [ -n "${SUDO_USER:-}" ]; then
	chown -R "$REAL_USER" "$CONFIG_DIR" "$REAL_DATA" "$REAL_CLAUDE_CONFIG"
	chown "$REAL_USER" "$REAL_CLAUDE_AUTH"
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
PASST_PID=""
trap 'kill "$PASST_PID" 2>/dev/null || true; rm -rf "'"$RUNTIME"'"' EXIT

ln -sfn "$REAL_DATA" "$RUNTIME/data"
ln -sfn "$REAL_CLAUDE_CONFIG" "$RUNTIME/claude-config"
ln -sfn "$REAL_CLAUDE_AUTH" "$RUNTIME/claude-auth.json"

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
	-e "s|${BASE_RUNTIME}/|${RUNTIME}/|g"
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
