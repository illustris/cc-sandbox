usage() {
	cat <<'EOF'
Usage: cc-sandbox [OPTIONS]

Run Claude Code in an isolated QEMU microvm.

Options:
  --name NAME    Use a named instance (creates it on first run)
  --vcpu N       Override vCPU count (default: config or 16)
  --mem N        Override RAM in megabytes (default: config or 32768)
  --init-only    Run all setup steps but do not start the VM
  --list         List all instances with their ports and status
  --help         Show this help message

Environment variables:
  CC_SANDBOX_DATA           Persistent data volume (default: ~/.local/share/cc-sandbox)
  CC_SANDBOX_CLAUDE_CONFIG  Host Claude config dir (default: ~/.claude)
  CC_SANDBOX_CLAUDE_AUTH    Auth token file (default: ~/.claude.json)

Examples:
  cc-sandbox                          Start the default instance
  cc-sandbox --name work              Start a named instance
  cc-sandbox --name work --vcpu 8     Named instance with 8 cores
  cc-sandbox --list                   Show all instances
  cc-sandbox --init-only              Set up without booting
EOF
	exit 0
}

INIT_ONLY=0
FLAG_VCPU=""
FLAG_MEM=""
INSTANCE_NAME=""
LIST_INSTANCES=0
while [ $# -gt 0 ]; do
	case "$1" in
		--init-only) INIT_ONLY=1 ;;
		--vcpu) FLAG_VCPU="$2"; shift ;;
		--mem) FLAG_MEM="$2"; shift ;;
		--name) INSTANCE_NAME="$2"; shift ;;
		--list) LIST_INSTANCES=1 ;;
		--help) usage ;;
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

# -- Paths ---------------------------------------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/cc-sandbox"
BASE_DATA="${CC_SANDBOX_DATA:-$HOME/.local/share/cc-sandbox}"
REAL_CLAUDE_CONFIG="${CC_SANDBOX_CLAUDE_CONFIG:-$HOME/.claude}"
REAL_CLAUDE_AUTH="${CC_SANDBOX_CLAUDE_AUTH:-$HOME/.claude.json}"
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
	echo "Instances:"
	if [ -f "$CONFIG_DIR/config.json" ]; then
		ssh_p=$(jq -r '.sshPort // 2222' "$CONFIG_DIR/config.json")
		http_p=$(jq -r '.httpPort // 8080' "$CONFIG_DIR/config.json")
		running=""
		if [ -f "$BASE_RUNTIME/pid" ] && kill -0 "$(cat "$BASE_RUNTIME/pid")" 2>/dev/null; then
			running=" (running)"
		fi
		echo "  (default)  ssh:$ssh_p  http:$http_p$running"
	fi
	if [ -d "$CONFIG_DIR/instances" ]; then
		for dir in "$CONFIG_DIR/instances"/*/; do
			[ -d "$dir" ] || continue
			name=$(basename "$dir")
			cfg="$dir/config.json"
			if [ -f "$cfg" ]; then
				ssh_p=$(jq -r '.sshPort // 2222' "$cfg")
				http_p=$(jq -r '.httpPort // 8080' "$cfg")
				running=""
				inst_runtime="${BASE_RUNTIME}-${name}"
				if [ -f "$inst_runtime/pid" ] && kill -0 "$(cat "$inst_runtime/pid")" 2>/dev/null; then
					running=" (running)"
				fi
				echo "  $name  ssh:$ssh_p  http:$http_p$running"
			fi
		done
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

	if [ ! -f "$CONFIG_DIR/config.json" ] && [ -z "$INSTANCE_NAME" ]; then
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			'{
				vcpu: $vcpu,
				mem: $mem,
				sshPort: 2222,
				httpPort: 8080,
				overlaySize: "128M",
				storeOverlaySize: "16G",
				bindAddr: "127.0.0.1"
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
				bindAddr: "127.0.0.1"
			}' > "$CONFIG_DIR/config.json"
		fi
		read -r next_ssh next_http <<< "$(next_available_ports)"
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--argjson ssh "$next_ssh" \
			--argjson http "$next_http" \
			'{
				vcpu: $vcpu,
				mem: $mem,
				sshPort: $ssh,
				httpPort: $http,
				overlaySize: "128M",
				storeOverlaySize: "16G",
				bindAddr: "127.0.0.1"
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
trap 'rm -rf "'"$RUNTIME"'"' EXIT

ln -sfn "$REAL_DATA" "$RUNTIME/data"
ln -sfn "$REAL_CLAUDE_CONFIG" "$RUNTIME/claude-config"
ln -sfn "$REAL_CLAUDE_AUTH" "$RUNTIME/claude-auth.json"

# -- Patch the microvm runner with runtime QEMU settings -----------
sed -E \
	-e "s/( )-smp [0-9]+/\1-smp $VCPU/" \
	-e "s/( )-m [0-9]+/\1-m $MEM/" \
	-e "s/hostfwd=tcp:[^-]*-:22/hostfwd=tcp:$BIND_ADDR:$SSH_PORT-:22/g" \
	-e "s/hostfwd=tcp:[^-]*-:8080/hostfwd=tcp:$BIND_ADDR:$HTTP_PORT-:8080/g" \
	-e "s|${BASE_RUNTIME}/|${RUNTIME}/|g" \
	"@runner@/bin/microvm-run" > "$RUNTIME/run"
chmod +x "$RUNTIME/run"

if [ "$INIT_ONLY" -eq 1 ]; then
	echo "Init complete${INSTANCE_NAME:+ (instance \"$INSTANCE_NAME\")}. Runtime directory: $RUNTIME"
	exit 0
fi

cd "$RUNTIME"
exec "$RUNTIME/run"
