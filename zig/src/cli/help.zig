// Per-verb help text and the top-level `cogbox --help` output.
//
// Each verb's own file holds the body it wants to print when invoked
// with --help; this module just enumerates them for the top-level lister.

const std = @import("std");
const util = @import("util.zig");

pub const TOP_LEVEL =
	\\cogbox - run coding-agent harnesses (claude-code, opencode, codex) in an isolated QEMU microvm
	\\
	\\Usage:
	\\  cogbox [VERB] [OPTIONS]
	\\
	\\Verbs:
	\\  start     Launch the VM in the background, then SSH into it (default).
	\\            --no-ssh just returns; -f/--foreground attaches the console.
	\\  console   Attach the serial console of a running instance (Ctrl-] detaches)
	\\  monitor   Attach the QEMU monitor of a running instance (Ctrl-] detaches)
	\\  stop      Stop a running instance
	\\  restart   Stop then start
	\\  status    Print whether an instance is running, its ports, and net mode
	\\  list      List all instances
	\\  init      Create instance config and host directories without launching
	\\  ssh       Connect to a running instance via SSH
	\\  rules     Manage CIDR allow/deny rules for an instance
	\\  remap     Manage TCP destination-remap rules
	\\  help      Show help for a verb (cogbox help VERB)
	\\
	\\Common options:
	\\  -n, --name NAME    Instance name (default: "default")
	\\  -f, --foreground   (start) attach the serial console after launch
	\\      --no-ssh       (start) don't auto-ssh; just launch and return
	\\  -h, --help         Show help and exit
	\\
	\\Run 'cogbox VERB --help' for verb-specific options. Bare 'cogbox' is
	\\equivalent to 'cogbox start' -- it launches the VM in the background and
	\\then opens an SSH session into it (pass --no-ssh to just return). The VM's
	\\serial console and QEMU monitor live on per-instance sockets, so you can
	\\attach and detach (Ctrl-]) freely without stopping the VM.
	\\
	\\Network modes:
	\\  full              Unrestricted networking
	\\  none              Block all outbound traffic (QEMU restrict=on)
	\\  rules             Ordered CIDR allow/deny rules. Default. Seeded with
	\\                    denies for private (RFC1918), link-local (incl. cloud
	\\                    metadata 169.254.169.254), and bogon ranges, followed
	\\                    by allow 0.0.0.0/0 for the public internet.
	\\
	\\Paths (XDG basedir spec):
	\\  Config:  $XDG_CONFIG_HOME/cogbox        (default: ~/.config/cogbox)
	\\  Data:    $XDG_DATA_HOME/cogbox          (default: ~/.local/share/cogbox)
	\\  Runtime: $XDG_RUNTIME_DIR/cogbox        (default: /run/user/$UID/cogbox)
	\\
	\\Environment variables:
	\\  COGBOX_DATA              Override the data root.
	\\  COGBOX_CLAUDE_CONFIG     Host claude-code config dir (default: ~/.claude)
	\\  COGBOX_CLAUDE_AUTH       claude-code auth token file (default: ~/.claude.json)
	\\  COGBOX_OPENCODE_CONFIG   Host opencode config dir
	\\  COGBOX_OPENCODE_DATA     Host opencode data dir, includes auth.json
	\\  COGBOX_CODEX_HOME        Host codex home dir (default: ~/.codex), includes auth.json
	\\
	\\Exit codes:
	\\  0   success
	\\  3   status: instance is stopped
	\\  64  bad CLI args, unknown verb or flag (EX_USAGE)
	\\  65  bad data: invalid CIDR, integer, name (EX_DATAERR)
	\\  66  missing config: instance never inited (EX_NOINPUT)
	\\  70  internal/system error (EX_SOFTWARE)
	\\  75  already running, port collision (EX_TEMPFAIL)
	\\
;

pub const START =
	\\cogbox start - launch the VM in the background, then SSH in (the default verb)
	\\
	\\Usage:
	\\  cogbox start [OPTIONS]
	\\  cogbox       [OPTIONS]            (bare cogbox is equivalent)
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\      --no-ssh          Don't open an SSH session after launch; just start
	\\                        the VM in the background and return.
	\\  -f, --foreground      Attach the serial console after launch instead of
	\\                        sshing. Detaching (Ctrl-]) leaves the VM running.
	\\  --vcpu N              vCPU count (default: 16; or value from config.json)
	\\  --mem N               RAM in megabytes (default: 32768; or from config.json)
	\\  --network MODE        Network mode: full, none, or rules (default: rules)
	\\  --no-auto-keys        On first init, leave authorized_keys empty instead of
	\\                        seeding from ~/.ssh/*.pub and ssh-add -L
	\\  -y, --yes             Skip the harness-selection prompt on first init
	\\  -h, --help            Show this help and exit
	\\
	\\The VM always runs as a background daemon. By default, once QEMU is up
	\\cogbox waits for the guest's sshd to start accepting connections and then
	\\execs `ssh` into the guest; when that session ends the VM keeps running
	\\(stop it with `cogbox stop`). Press Ctrl-C during the wait to leave the VM
	\\running and drop back to your shell.
	\\
	\\First-run setup prompts are shown in the foreground; the daemon's own
	\\output goes to <runtime>/cogbox.log, and the guest serial console is
	\\captured to <runtime>/console.log. Exits 75 if an instance with the same
	\\name is already running.
	\\
	\\Examples:
	\\  cogbox                           Start the default instance and SSH in
	\\  cogbox --no-ssh                  Start in the background and return
	\\  cogbox -f                        Start and attach the serial console
	\\  cogbox --name work               Start the "work" instance and SSH in
	\\  cogbox --vcpu 8 --mem 16384      Start with custom resources, then SSH in
	\\  cogbox --network none --no-ssh   Start fully isolated, don't connect
	\\
	\\See also: cogbox ssh, cogbox console, cogbox monitor, cogbox status, cogbox stop
	\\
;

pub const CONSOLE =
	\\cogbox console - attach the serial console of a running instance
	\\
	\\Usage:
	\\  cogbox console [OPTIONS]
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  -h, --help            Show this help and exit
	\\
	\\Connects to the guest's serial console (<runtime>/console.sock) and relays
	\\your terminal to it in raw mode. Recent console history is replayed first,
	\\then the session goes live. Press Ctrl-] to detach; the VM keeps running.
	\\Only one console attachment is possible at a time.
	\\
	\\See also: cogbox monitor, cogbox start -f
	\\
;

pub const MONITOR =
	\\cogbox monitor - attach the QEMU (HMP) monitor of a running instance
	\\
	\\Usage:
	\\  cogbox monitor [OPTIONS]
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  -h, --help            Show this help and exit
	\\
	\\Connects to the human QEMU monitor (<runtime>/monitor.sock) where you can
	\\type commands like 'info status', 'info block', or 'system_powerdown'.
	\\Press Ctrl-] to detach; the VM keeps running. Only one monitor attachment
	\\is possible at a time.
	\\
	\\See also: cogbox console, cogbox stop
	\\
;

pub const STOP =
	\\cogbox stop - stop a running instance
	\\
	\\Usage:
	\\  cogbox stop [OPTIONS]
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  --force               After 10s of SIGTERM with no exit, send SIGKILL
	\\  -h, --help            Show this help and exit
	\\
	\\Idempotent: if no PID file exists or the process is already dead,
	\\stop is a no-op exit 0.
	\\
;

pub const RESTART =
	\\cogbox restart - stop then start
	\\
	\\Usage:
	\\  cogbox restart [OPTIONS]
	\\
	\\Accepts the same options as `cogbox start`, including its default behavior:
	\\once the VM is back up it waits for sshd and opens an SSH session. Pass
	\\--no-ssh to just restart the daemon and return, or -f to attach the console.
	\\
;

pub const STATUS =
	\\cogbox status - print whether an instance is running
	\\
	\\Usage:
	\\  cogbox status [OPTIONS]
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  -h, --help            Show this help and exit
	\\
	\\Prints one of:
	\\  running pid=N ssh=HOST:PORT http=HOST:PORT net=MODE
	\\  stopped
	\\
	\\Exit codes:
	\\  0  running
	\\  3  stopped
	\\  64 unknown instance (no config.json)
	\\
;

pub const LIST =
	\\cogbox list - list all instances
	\\
	\\Usage:
	\\  cogbox list [--json]
	\\
	\\Options:
	\\  --json                Emit one JSON object per instance instead of text
	\\  -h, --help            Show this help and exit
	\\
;

pub const INIT =
	\\cogbox init - create instance config and host directories without launching
	\\
	\\Usage:
	\\  cogbox init [OPTIONS]
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  --vcpu N              vCPU count to bake into the new config
	\\  --mem N               RAM in megabytes to bake into the new config
	\\  --network MODE        Network mode: full, none, or rules
	\\  --no-auto-keys        Leave authorized_keys empty instead of seeding it
	\\  -y, --yes             Skip the harness-selection prompt
	\\  -h, --help            Show this help and exit
	\\
	\\Idempotent. Re-running on an existing instance only seeds anything that's
	\\missing; existing config is preserved.
	\\
;

pub const SSH =
	\\cogbox ssh - connect to a running instance via SSH
	\\
	\\Usage:
	\\  cogbox ssh [OPTIONS] [-- REMOTE_COMMAND...]
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  -h, --help            Show this help and exit
	\\
	\\Reads the live SSH host:port from <runtime>/ssh-endpoint, so it works
	\\even with auto-assigned ports. Disables host-key checking since the
	\\guest's root disk is ephemeral and host keys regenerate every boot.
	\\
	\\Examples:
	\\  cogbox ssh                          Open an interactive shell
	\\  cogbox ssh -- htop                  Run htop on the default instance
	\\  cogbox ssh --name work -- uname -a  Run on the "work" instance
	\\
;

pub const RULES =
	\\cogbox rules - manage netfilter rules for an instance
	\\
	\\Usage:
	\\  cogbox rules [-n NAME] list
	\\  cogbox rules [-n NAME] add allow|deny CIDR [--at N]
	\\  cogbox rules [-n NAME] del INDEX
	\\  cogbox rules [-n NAME] set            (reads rules from stdin)
	\\
	\\Options:
	\\  -n, --name NAME       Instance name (default: "default")
	\\  -h, --help            Show this help and exit
	\\
	\\Rules apply only when the instance's network mode is "rules". The
	\\evaluator walks the list top-down and stops at the first match; an
	\\unmatched destination is allowed.
	\\
	\\If the instance is running, edits hot-reload via SIGUSR1 to passt
	\\(no VM restart needed).
	\\
;

pub const REMAP =
	\\cogbox remap - manage TCP destination-remap rules
	\\
	\\Usage:
	\\  cogbox remap [-n NAME] list
	\\  cogbox remap [-n NAME] add FROM TO [--at N]
	\\  cogbox remap [-n NAME] del INDEX
	\\  cogbox remap [-n NAME] set            (reads rules from stdin)
	\\
	\\Spec syntax (v1: tcp only, single-host target):
	\\  FROM:  tcp CIDR:PORT       e.g. "tcp 0.0.0.0/0:443"
	\\  TO:    tcp IP[:PORT]       e.g. "tcp 127.0.0.1:18080"
	\\
	\\When a TCP connect() inside the LD_PRELOAD'd network process
	\\matches FROM, the shim rewrites the destination to TO and drives
	\\a SOCKS5 v5 CONNECT handshake on the same fd carrying the
	\\original (IP, port). The downstream proxy thus sees the guest's
	\\real intended destination.
	\\
	\\Examples:
	\\  cogbox remap add "tcp 0.0.0.0/0:443" "tcp 127.0.0.1:18080"
	\\  cogbox remap add "tcp 1.2.3.0/24:80" "tcp 10.0.0.1:8080" --at 1
	\\
	\\If the instance is running, edits hot-reload via SIGUSR1 to passt
	\\(no VM restart needed).
	\\
;

pub fn forVerb(verb: []const u8) ?[]const u8 {
	if (std.mem.eql(u8, verb, "start")) return START;
	if (std.mem.eql(u8, verb, "console")) return CONSOLE;
	if (std.mem.eql(u8, verb, "monitor")) return MONITOR;
	if (std.mem.eql(u8, verb, "stop")) return STOP;
	if (std.mem.eql(u8, verb, "restart")) return RESTART;
	if (std.mem.eql(u8, verb, "status")) return STATUS;
	if (std.mem.eql(u8, verb, "list")) return LIST;
	if (std.mem.eql(u8, verb, "init")) return INIT;
	if (std.mem.eql(u8, verb, "ssh")) return SSH;
	if (std.mem.eql(u8, verb, "rules")) return RULES;
	if (std.mem.eql(u8, verb, "remap")) return REMAP;
	return null;
}

pub fn print(io: std.Io, body: []const u8) !void {
	try util.writeStdout(io, body);
}
