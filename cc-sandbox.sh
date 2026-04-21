INIT_ONLY=0
FLAG_VCPU=""
FLAG_MEM=""
while [ $# -gt 0 ]; do
	case "$1" in
		--init-only) INIT_ONLY=1 ;;
		--vcpu) FLAG_VCPU="$2"; shift ;;
		--mem) FLAG_MEM="$2"; shift ;;
	esac
	shift
done

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/cc-sandbox"

REAL_DATA="${CC_SANDBOX_DATA:-$HOME/.local/share/cc-sandbox}"
REAL_CLAUDE_CONFIG="${CC_SANDBOX_CLAUDE_CONFIG:-$HOME/.claude}"
REAL_CLAUDE_AUTH="${CC_SANDBOX_CLAUDE_AUTH:-$HOME/.claude.json}"

# -- First-time init: collect missing items, prompt once --------
ITEMS=()
if [ ! -f "$CONFIG_DIR/config.json" ]; then
	ITEMS+=("$CONFIG_DIR/config.json  (default settings)")
fi
if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
	ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, empty)")
fi
if [ ! -d "$REAL_DATA" ]; then
	ITEMS+=("$REAL_DATA/  (VM data)")
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
	if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
		touch "$CONFIG_DIR/authorized_keys"
	fi
	if [ ! -f "$REAL_CLAUDE_AUTH" ]; then
		echo '{}' > "$REAL_CLAUDE_AUTH"
		chmod 600 "$REAL_CLAUDE_AUTH"
	fi
fi

# -- Validate and read runtime config --------------------------
if ! jq empty "$CONFIG_DIR/config.json" 2>/dev/null; then
	echo "Error: invalid JSON in $CONFIG_DIR/config.json"
	exit 1
fi

VCPU="${FLAG_VCPU:-$(jq -r '.vcpu // 16' "$CONFIG_DIR/config.json")}"
MEM="${FLAG_MEM:-$(jq -r '.mem // 32768' "$CONFIG_DIR/config.json")}"
SSH_PORT=$(jq -r '.sshPort // 2222' "$CONFIG_DIR/config.json")
HTTP_PORT=$(jq -r '.httpPort // 8080' "$CONFIG_DIR/config.json")
OVERLAY_SIZE=$(jq -r '.overlaySize // "128M"' "$CONFIG_DIR/config.json")
STORE_OVERLAY_SIZE=$(jq -r '.storeOverlaySize // "16G"' "$CONFIG_DIR/config.json")
BIND_ADDR=$(jq -r '.bindAddr // "127.0.0.1"' "$CONFIG_DIR/config.json")

# -- Write VM-side config into the data directory --------------
mkdir -p "$REAL_DATA/.config"
echo "$OVERLAY_SIZE" > "$REAL_DATA/.config/overlay-size"
echo "$STORE_OVERLAY_SIZE" > "$REAL_DATA/.config/store-overlay-size"
cp "$CONFIG_DIR/authorized_keys" "$REAL_DATA/.config/authorized_keys"

# -- Set up runtime symlink directory for QEMU -----------------
RUNTIME="@runtimeDir@"
if [ -e "$RUNTIME" ]; then
	if [ -f "$RUNTIME/pid" ] && kill -0 "$(cat "$RUNTIME/pid")" 2>/dev/null; then
		echo "Another cc-sandbox instance is running (PID $(cat "$RUNTIME/pid"))."
		exit 1
	fi
	rm -rf "$RUNTIME"
fi
mkdir -p "$RUNTIME"
echo "$$" > "$RUNTIME/pid"
trap 'rm -rf "@runtimeDir@"' EXIT

ln -sfn "$REAL_DATA" "$RUNTIME/data"
ln -sfn "$REAL_CLAUDE_CONFIG" "$RUNTIME/claude-config"
ln -sfn "$REAL_CLAUDE_AUTH" "$RUNTIME/claude-auth.json"

# -- Patch the microvm runner with runtime QEMU settings -------
sed -E \
	-e "s/( )-smp [0-9]+/\1-smp $VCPU/" \
	-e "s/( )-m [0-9]+/\1-m $MEM/" \
	-e "s/hostfwd=tcp:[^-]*-:22/hostfwd=tcp:$BIND_ADDR:$SSH_PORT-:22/g" \
	-e "s/hostfwd=tcp:[^-]*-:8080/hostfwd=tcp:$BIND_ADDR:$HTTP_PORT-:8080/g" \
	"@runner@/bin/microvm-run" > "$RUNTIME/run"
chmod +x "$RUNTIME/run"

if [ "$INIT_ONLY" -eq 1 ]; then
	echo "Init complete. Runtime directory: $RUNTIME"
	exit 0
fi

exec "$RUNTIME/run"
