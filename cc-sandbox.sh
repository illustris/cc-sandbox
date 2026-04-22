usage() {
	cat <<'EOF'
Usage: cc-sandbox [OPTIONS]
       cc-sandbox rules COMMAND [--name NAME]

Run Claude Code in an isolated QEMU microvm.

Options:
  --name NAME      Use a named instance (creates it on first run)
  --vcpu N         Set vCPU count (default: config or 16)
  --mem N          Set RAM in megabytes (default: config or 32768)
  --network MODE   Network mode: full, none, or rules (default: config or full)
  --init-only      Run all setup steps but do not start the VM
  --list           List all instances with their ports and status
  --help           Show this help message

Network modes:
  "full"           Unrestricted networking (default)
  "none"           Block all outbound traffic (QEMU restrict=on)
  "rules"          Ordered CIDR allow/deny rules (LD_PRELOAD filter on passt)

Rules subcommands:
  rules list                     List current rules with indices
  rules add allow|deny CIDR      Append a rule
  rules del INDEX                Delete a rule by index (1-based)
  rules set                      Replace all rules from stdin

Environment variables:
  CC_SANDBOX_DATA           Persistent data volume (default: ~/.local/share/cc-sandbox)
  CC_SANDBOX_CLAUDE_CONFIG  Host Claude config dir (default: ~/.claude)
  CC_SANDBOX_CLAUDE_AUTH    Auth token file (default: ~/.claude.json)

Examples:
  cc-sandbox                          Start the default instance
  cc-sandbox --name work              Start a named instance
  cc-sandbox --name work --vcpu 8     Named instance with 8 cores
  cc-sandbox --network none           Start fully isolated
  cc-sandbox --network rules          Init with deny-all rules mode
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
RULES_CMD=""
RULES_ACTION=""
RULES_ARG=""
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
			if [ $# -lt 2 ]; then
				echo "Error: rules requires a subcommand (list, add, del, set)."
				exit 1
			fi
			RULES_CMD="$2"; shift
			case "$RULES_CMD" in
				add)
					if [ $# -lt 3 ]; then
						echo "Error: rules add requires ACTION CIDR (e.g., rules add allow 10.0.0.0/8)."
						exit 1
					fi
					RULES_ACTION="$2"; RULES_ARG="$3"; shift 2
					;;
				del)
					if [ $# -lt 2 ]; then
						echo "Error: rules del requires INDEX."
						exit 1
					fi
					RULES_ARG="$2"; shift
					;;
				list|set) ;;
				*) echo "Error: unknown rules subcommand \"$RULES_CMD\"."; exit 1 ;;
			esac
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

if [ -n "$INSTANCE_NAME" ]; then
	INSTANCE_CONFIG_DIR="$CONFIG_DIR/instances/$INSTANCE_NAME"
	REAL_DATA="$BASE_DATA/instances/$INSTANCE_NAME"
	RUNTIME="${BASE_RUNTIME}-${INSTANCE_NAME}"
else
	INSTANCE_CONFIG_DIR="$CONFIG_DIR"
	REAL_DATA="$BASE_DATA"
	RUNTIME="$BASE_RUNTIME"
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
	if [ -f "$CONFIG_DIR/config.json" ]; then
		ssh_p=$(jq -r '.sshPort // 2222' "$CONFIG_DIR/config.json")
		http_p=$(jq -r '.httpPort // 8080' "$CONFIG_DIR/config.json")
		net=$(net_label "$CONFIG_DIR/config.json")
		running=""
		if [ -f "$BASE_RUNTIME/pid" ] && kill -0 "$(cat "$BASE_RUNTIME/pid")" 2>/dev/null; then
			running=" (running)"
		fi
		echo "  (default)  ssh:$ssh_p  http:$http_p  net:$net$running"
	fi
	if [ -d "$CONFIG_DIR/instances" ]; then
		for dir in "$CONFIG_DIR/instances"/*/; do
			[ -d "$dir" ] || continue
			name=$(basename "$dir")
			cfg="$dir/config.json"
			if [ -f "$cfg" ]; then
				ssh_p=$(jq -r '.sshPort // 2222' "$cfg")
				http_p=$(jq -r '.httpPort // 8080' "$cfg")
				net=$(net_label "$cfg")
				running=""
				inst_runtime="${BASE_RUNTIME}-${name}"
				if [ -f "$inst_runtime/pid" ] && kill -0 "$(cat "$inst_runtime/pid")" 2>/dev/null; then
					running=" (running)"
				fi
				echo "  $name  ssh:$ssh_p  http:$http_p  net:$net$running"
			fi
		done
	fi
	exit 0
fi

# -- Rules subcommand ----------------------------------------------
if [ -n "$RULES_CMD" ]; then
	ACTIVE_CONFIG="$INSTANCE_CONFIG_DIR/config.json"
	if [ ! -f "$ACTIVE_CONFIG" ]; then
		echo "Error: no config found at $ACTIVE_CONFIG"
		exit 1
	fi

	# Verify it's in rules mode
	NETWORK_RAW=$(jq -c '.network // "full"' "$ACTIVE_CONFIG")
	if [ "$NETWORK_RAW" = '"full"' ] || [ "$NETWORK_RAW" = '"none"' ]; then
		echo "Error: instance is not in rules mode (network is $(echo "$NETWORK_RAW" | tr -d '"'))."
		echo "Set network to rules mode first: edit $ACTIVE_CONFIG or reinit with --network rules."
		exit 1
	fi

	case "$RULES_CMD" in
		list)
			jq -r '.network.rules | to_entries[] | "\(.key + 1): \(if .value.allow then "allow \(.value.allow)" elif .value.deny then "deny \(.value.deny)" else "unknown" end)"' "$ACTIVE_CONFIG"
			;;
		add)
			if [ "$RULES_ACTION" != "allow" ] && [ "$RULES_ACTION" != "deny" ]; then
				echo "Error: action must be \"allow\" or \"deny\"."
				exit 1
			fi
			jq --tab --arg action "$RULES_ACTION" --arg cidr "$RULES_ARG" \
				'.network.rules += [{($action): $cidr}]' "$ACTIVE_CONFIG" > "$ACTIVE_CONFIG.tmp" \
				&& mv "$ACTIVE_CONFIG.tmp" "$ACTIVE_CONFIG"
			echo "Added: $RULES_ACTION $RULES_ARG"
			;;
		del)
			idx=$((RULES_ARG - 1))
			if [ "$idx" -lt 0 ]; then
				echo "Error: index must be >= 1."
				exit 1
			fi
			jq --tab --argjson idx "$idx" \
				'.network.rules |= (.[0:$idx] + .[$idx+1:])' "$ACTIVE_CONFIG" > "$ACTIVE_CONFIG.tmp" \
				&& mv "$ACTIVE_CONFIG.tmp" "$ACTIVE_CONFIG"
			echo "Deleted rule $RULES_ARG."
			;;
		set)
			# Read rules from stdin, convert to JSON array
			RULES_JSON="[]"
			while IFS= read -r line; do
				trimmed=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
				[ -z "$trimmed" ] && continue
				[[ "$trimmed" == \#* ]] && continue
				action=$(echo "$trimmed" | cut -d' ' -f1)
				cidr=$(echo "$trimmed" | cut -d' ' -f2)
				if [ "$action" != "allow" ] && [ "$action" != "deny" ]; then
					echo "Error: invalid action \"$action\" in line: $trimmed"
					exit 1
				fi
				RULES_JSON=$(echo "$RULES_JSON" | jq --arg a "$action" --arg c "$cidr" '. + [{($a): $c}]')
			done
			jq --tab --argjson rules "$RULES_JSON" '.network.rules = $rules' "$ACTIVE_CONFIG" > "$ACTIVE_CONFIG.tmp" \
				&& mv "$ACTIVE_CONFIG.tmp" "$ACTIVE_CONFIG"
			echo "Rules replaced."
			;;
	esac

	# Signal running passt to reload rules
	if [ -f "$RUNTIME/passt.pid" ] && kill -0 "$(cat "$RUNTIME/passt.pid")" 2>/dev/null; then
		# Regenerate the runtime rules file
		jq -r '.network.rules[] |
			if .allow then "allow \(.allow)"
			elif .deny then "deny \(.deny)"
			else empty end' "$ACTIVE_CONFIG" > "$RUNTIME/netfilter-rules"
		kill -USR1 "$(cat "$RUNTIME/passt.pid")"
		echo "Rules reloaded (signaled running instance)."
	fi
	exit 0
fi

# -- Auto-port assignment -----------------------------------------
next_available_ports() {
	local max_ssh=2222
	local max_http=8080

	if [ -f "$CONFIG_DIR/config.json" ]; then
		local s h
		s=$(jq -r '.sshPort // 0' "$CONFIG_DIR/config.json")
		h=$(jq -r '.httpPort // 0' "$CONFIG_DIR/config.json")
		[ "$s" -gt "$max_ssh" ] && max_ssh=$s
		[ "$h" -gt "$max_http" ] && max_http=$h
	fi

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
if [ ! -f "$CONFIG_DIR/config.json" ] && [ -z "$INSTANCE_NAME" ]; then
	ITEMS+=("$CONFIG_DIR/config.json  (default settings)")
fi
if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
	ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, empty)")
fi
if [ -n "$INSTANCE_NAME" ] && [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
	ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (instance \"$INSTANCE_NAME\" settings)")
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

	mkdir -p "$CONFIG_DIR" "$REAL_DATA" "$REAL_CLAUDE_CONFIG"
	[ -n "$INSTANCE_NAME" ] && mkdir -p "$INSTANCE_CONFIG_DIR"

	INIT_VCPU="${FLAG_VCPU:-16}"
	INIT_MEM="${FLAG_MEM:-32768}"
	INIT_NETWORK="${FLAG_NETWORK:-full}"

	# Build network value for config: "full"/"none" as string, rules as object
	if [ "$INIT_NETWORK" = "rules" ]; then
		NETWORK_JQ='{"rules":[]}'
	else
		NETWORK_JQ="\"$INIT_NETWORK\""
	fi

	if [ ! -f "$CONFIG_DIR/config.json" ] && [ -z "$INSTANCE_NAME" ]; then
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--argjson network "$NETWORK_JQ" \
			'{
				vcpu: $vcpu,
				mem: $mem,
				sshPort: 2222,
				httpPort: 8080,
				overlaySize: "128M",
				storeOverlaySize: "16G",
				bindAddr: "127.0.0.1",
				network: $network
			}' > "$CONFIG_DIR/config.json"
	fi

	if [ -n "$INSTANCE_NAME" ] && [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
		if [ ! -f "$CONFIG_DIR/config.json" ]; then
			jq -n --tab '{
				vcpu: 16,
				mem: 32768,
				sshPort: 2222,
				httpPort: 8080,
				overlaySize: "128M",
				storeOverlaySize: "16G",
				bindAddr: "127.0.0.1",
				network: "full"
			}' > "$CONFIG_DIR/config.json"
		fi
		read -r next_ssh next_http <<< "$(next_available_ports)"
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--argjson network "$NETWORK_JQ" \
			--argjson ssh "$next_ssh" \
			--argjson http "$next_http" \
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
		echo "Instance \"$INSTANCE_NAME\" ports: SSH=$next_ssh HTTP=$next_http"
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
