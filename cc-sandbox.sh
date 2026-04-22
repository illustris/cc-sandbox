usage() {
	cat <<'EOF'
Usage: cc-sandbox [OPTIONS]

Run Claude Code in an isolated QEMU microvm.

Options:
  --name NAME      Use a named instance (creates it on first run)
  --vcpu N         Set vCPU count (default: config or 16)
  --mem N          Set RAM in megabytes (default: config or 32768)
  --network MODE   Network mode: full or none (default: config or full)
  --init-only      Run all setup steps but do not start the VM
  --list           List all instances with their ports and status
  --help           Show this help message

Network modes (config.json):
  "full"           Unrestricted networking (default)
  "none"           Block all outbound traffic (QEMU restrict=on)
  {"rules":[...]}  Ordered CIDR allow/deny rules (requires sudo)

Environment variables:
  CC_SANDBOX_DATA           Persistent data volume (default: ~/.local/share/cc-sandbox)
  CC_SANDBOX_CLAUDE_CONFIG  Host Claude config dir (default: ~/.claude)
  CC_SANDBOX_CLAUDE_AUTH    Auth token file (default: ~/.claude.json)

Examples:
  cc-sandbox                          Start the default instance
  cc-sandbox --name work              Start a named instance
  cc-sandbox --name work --vcpu 8     Named instance with 8 cores
  cc-sandbox --network none           Start fully isolated
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
if [ -n "$FLAG_NETWORK" ] && [ "$FLAG_NETWORK" != "full" ] && [ "$FLAG_NETWORK" != "none" ]; then
	echo "Error: --network must be \"full\" or \"none\"."
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

	if [ ! -f "$CONFIG_DIR/config.json" ] && [ -z "$INSTANCE_NAME" ]; then
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--arg network "$INIT_NETWORK" \
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
			--arg network "$INIT_NETWORK" \
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

# -- Validate rules mode requires root -----------------------------
if [ "$NETWORK_MODE" = "rules" ] && [ "$(id -u)" -ne 0 ]; then
	echo "Error: network rules mode requires root. Run with: sudo $(basename "$0")"
	exit 1
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

# -- Resolve host DNS for passt in rules mode ----------------------
HOST_DNS=""
if [ "$NETWORK_MODE" = "rules" ]; then
	HOST_DNS=$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)
	if [ "${HOST_DNS:-}" = "127.0.0.53" ] || [ "${HOST_DNS:-}" = "127.0.0.1" ]; then
		HOST_DNS=$(resolvectl dns 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
	fi
	HOST_DNS="${HOST_DNS:-1.1.1.1}"
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
	# -- Derive unique /30 subnet from SSH port --
	SUBNET_ID=$((SSH_PORT - 2222))
	NETNS_HOST_IP="172.31.$((SUBNET_ID / 64)).$((SUBNET_ID % 64 * 4 + 1))"
	NETNS_NS_IP="172.31.$((SUBNET_ID / 64)).$((SUBNET_ID % 64 * 4 + 2))"
	NETNS_CIDR="172.31.$((SUBNET_ID / 64)).$((SUBNET_ID % 64 * 4))/30"
	NETNS_NAME="cc-sandbox-$$"
	VETH_HOST="vc$$"
	VETH_NS="vn$$"

	# -- Create namespace and veth pair --
	ip netns add "$NETNS_NAME"
	ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
	ip link set "$VETH_NS" netns "$NETNS_NAME"
	ip addr add "$NETNS_HOST_IP/30" dev "$VETH_HOST"
	ip link set "$VETH_HOST" up
	ip netns exec "$NETNS_NAME" ip addr add "$NETNS_NS_IP/30" dev "$VETH_NS"
	ip netns exec "$NETNS_NAME" ip link set "$VETH_NS" up
	ip netns exec "$NETNS_NAME" ip link set lo up
	ip netns exec "$NETNS_NAME" ip route add default via "$NETNS_HOST_IP"

	# -- NAT and forwarding --
	sysctl -qw net.ipv4.ip_forward=1
	iptables -t nat -A POSTROUTING -s "$NETNS_CIDR" -j MASQUERADE

	# -- Generate and apply nftables rules inside namespace --
	NFT_RULES="table inet sandbox {
	    chain output {
	        type filter hook output priority 0; policy drop;
	        oifname \"lo\" accept
	        ct state established,related accept
	        meta l4proto { tcp, udp } th dport 53 accept
$(jq -r '.network.rules[] |
    if .allow then "        ip daddr \(.allow) accept"
    elif .deny then "        ip daddr \(.deny) drop"
    else empty end' "$ACTIVE_CONFIG")
	    }
	}"
	ip netns exec "$NETNS_NAME" nft -f - <<< "$NFT_RULES"

	# -- Cleanup handler --
	SOCAT_SSH_PID=""
	SOCAT_HTTP_PID=""
	cleanup_netns() {
		kill "$PASST_PID" "$SOCAT_SSH_PID" "$SOCAT_HTTP_PID" 2>/dev/null || true
		ip netns del "$NETNS_NAME" 2>/dev/null || true
		ip link del "$VETH_HOST" 2>/dev/null || true
		iptables -t nat -D POSTROUTING -s "$NETNS_CIDR" -j MASQUERADE 2>/dev/null || true
		rm -rf "$RUNTIME"
	}
	trap cleanup_netns EXIT

	# -- Port forwarding: host -> namespace --
	socat "TCP-LISTEN:$SSH_PORT,bind=$BIND_ADDR,fork,reuseaddr" "TCP:$NETNS_NS_IP:$SSH_PORT" &
	SOCAT_SSH_PID=$!
	socat "TCP-LISTEN:$HTTP_PORT,bind=$BIND_ADDR,fork,reuseaddr" "TCP:$NETNS_NS_IP:$HTTP_PORT" &
	SOCAT_HTTP_PID=$!

	# -- Start passt inside the namespace --
	chown "$REAL_USER" "$RUNTIME"
	ip netns exec "$NETNS_NAME" sysctl -qw net.ipv4.ping_group_range="0 2147483647"
	ip netns exec "$NETNS_NAME" sudo -u "$REAL_USER" \
		passt --foreground \
		--socket "$PASST_SOCK" -t "$SSH_PORT:22" -t "$HTTP_PORT:8080" \
		-D "$HOST_DNS" &
	PASST_PID=$!
	wait_for_passt

	# -- Launch QEMU inside the namespace as original user --
	cd "$RUNTIME"
	ip netns exec "$NETNS_NAME" sudo -u "$REAL_USER" "$RUNTIME/run"
elif [ "$NETWORK_MODE" != "none" ]; then
	# -- Full mode: start passt on host, then QEMU --
	passt --foreground --socket "$PASST_SOCK" \
		-t "$SSH_PORT:22" -t "$HTTP_PORT:8080" &
	PASST_PID=$!
	wait_for_passt
	cd "$RUNTIME"
	"$RUNTIME/run"
else
	cd "$RUNTIME"
	"$RUNTIME/run"
fi
