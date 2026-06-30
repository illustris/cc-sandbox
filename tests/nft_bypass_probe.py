#!/usr/bin/env python3
"""Standing egress-floor bypass probes for cogbox container mode (TODO).

Run INSIDE the test guest AFTER cogbox-nft-divert.sh has loaded its ruleset and
the dummy test IPs are assigned. This harness stands up the divert-shim, enforcer
and echo/raw listeners IN-PROCESS, fires exactly one probe per egress path, and
asserts each outcome. It is written to PROVE the leaks are CLOSED: the DROPPED
probes must now fail to be delivered, and each one has a bound listener so that --
absent the floor -- the packet WOULD be delivered (otherwise "not delivered" would
be a meaningless false pass).

Exits 0 iff every assertion holds, non-zero (with a per-line PASS/FAIL report) on
any leak. No internal identifiers: every address is from a documentation/test
range (RFC 5737 TEST-NET, RFC 4193 ULA, the conventional k8s 10.96/12 ClusterIP
block) and the only hostname is under the reserved .test TLD.
"""

import socket
import struct
import subprocess
import sys
import threading
import time

# --- test address plan (documentation/test ranges only) ----------------------
RESOLVER = "10.96.0.10"  # stub kube-dns ClusterIP -- the ONLY udp/53 dst allowed
ENFORCER = "10.96.12.34"  # enforcer Service ClusterIP (the nat carve-out dst)
ENF_PORT = 18443
SHIM = "127.0.0.1"  # the in-pod divert-shim REDIRECT target
SHIM_PORT = 18443
WEB = "192.0.2.10"  # raw-IP-literal TCP target (must be redirected)
NAMED_IP = "192.0.2.20"  # origin.test (in /etc/hosts) resolves here
NAMED = "origin.test"
TCP53 = "192.0.2.30"  # tcp/53 target (must be redirected, NOT sent direct)
UDP_OTHER = "198.51.100.10"  # udp/9999 target (must drop)
UDP53_BAD = "198.51.100.20"  # udp/53 to a NON-resolver (must drop)
ICMP_DST = "198.51.100.30"  # icmp echo target (must drop)
RAW_DST = "198.51.100.40"  # raw non-tcp/udp L4 target (must drop)
V6_DST = "fd00:dead:beef::10"  # any IPv6 dst (must drop)

SCTP_PROTO = 132  # IPPROTO_SCTP -- a representative non-tcp/udp IPv4 L4
SO_ORIGINAL_DST = 80  # getsockopt(SOL_IP, ...) -> the pre-REDIRECT tuple
MARK_CTL = b"COGBOX-RAW-CTL"  # loopback positive control for the raw path
MARK_DROP = b"COGBOX-RAW-DROP"  # the proto-132-to-non-loopback drop probe

_lock = threading.Lock()
shim_hits = []  # (ip, port) recovered from SO_ORIGINAL_DST per redirected conn
enf_hits = []  # peer addrs that reached the enforcer (carve-out, not redirected)
udp_seen = set()  # (ip, port) datagrams actually delivered to a UDP listener
raw_seen = []  # raw proto-132 packets (full bytes) delivered to the raw listener


# --- listeners: bind synchronously (so setup errors surface), serve in threads -
def _serve_tcp(family, ip, port, sink):
	s = socket.socket(family, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))
	s.listen(32)

	def loop():
		while True:
			try:
				conn, peer = s.accept()
			except OSError:
				return
			try:
				sink(conn, peer)
			except Exception:
				pass
			finally:
				try:
					conn.close()
				except OSError:
					pass

	threading.Thread(target=loop, daemon=True).start()


def _shim_sink(conn, peer):
	raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
	port = struct.unpack("!H", raw[2:4])[0]
	ip = socket.inet_ntoa(raw[4:8])
	with _lock:
		shim_hits.append((ip, port))


def _enf_sink(conn, peer):
	with _lock:
		enf_hits.append(peer)


def _serve_udp(family, ip, port):
	s = socket.socket(family, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))

	def loop():
		while True:
			try:
				s.recvfrom(2048)
			except OSError:
				return
			with _lock:
				udp_seen.add((ip, port))

	threading.Thread(target=loop, daemon=True).start()


def _serve_raw():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, SCTP_PROTO)

	def loop():
		while True:
			try:
				data, _ = s.recvfrom(65535)
			except OSError:
				return
			with _lock:
				raw_seen.append(bytes(data))

	threading.Thread(target=loop, daemon=True).start()


# --- helpers -----------------------------------------------------------------
def _wait_until(pred, timeout=2.0, interval=0.05):
	end = time.time() + timeout
	while time.time() < end:
		with _lock:
			if pred():
				return True
		time.sleep(interval)
	with _lock:
		return pred()


def _tcp_connect(host, port, timeout=2.0):
	conn = socket.create_connection((host, port), timeout=timeout)
	conn.close()


def _udp_send(family, ip, port, payload=b"cogbox-probe"):
	s = socket.socket(family, socket.SOCK_DGRAM)
	try:
		s.sendto(payload, (ip, port))
	except OSError:
		pass
	finally:
		s.close()


def _raw_send(ip, payload):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, SCTP_PROTO)
	try:
		s.sendto(payload, (ip, 0))
	except OSError:
		pass
	finally:
		s.close()


# --- probes: FORCED-THROUGH (redirected to the shim w/ correct orig dst) ------
def probe_forced_tcp_literal():
	_tcp_connect(WEB, 443)
	return _wait_until(lambda: (WEB, 443) in shim_hits)


def probe_forced_tcp_name():
	_tcp_connect(NAMED, 80)  # resolves via /etc/hosts -> NAMED_IP
	return _wait_until(lambda: (NAMED_IP, 80) in shim_hits)


def probe_forced_tcp_port53():
	# tcp/53 must be REDIRECTED (enforced), never confused with the udp/53 DNS
	# carve-out and sent direct.
	_tcp_connect(TCP53, 53)
	return _wait_until(lambda: (TCP53, 53) in shim_hits)


# --- probes: ENFORCER CARVE-OUT ----------------------------------------------
def probe_enforcer_carveout():
	# TCP to the enforcer ClusterIP:base RETURNs (anti-loop) and reaches the
	# enforcer directly -- it must NOT be redirected back onto the shim.
	before = len(enf_hits)
	_tcp_connect(ENFORCER, ENF_PORT)
	reached = _wait_until(lambda: len(enf_hits) > before)
	not_redirected = (ENFORCER, ENF_PORT) not in shim_hits
	return reached and not_redirected


def probe_enforcer_other_port_redirected():
	# Same ClusterIP, a DIFFERENT port: not the carve-out, so it IS redirected.
	_tcp_connect(ENFORCER, 9999)
	return _wait_until(lambda: (ENFORCER, 9999) in shim_hits)


# --- probes: ALLOWED ---------------------------------------------------------
def probe_udp_resolver_allowed():
	_udp_send(socket.AF_INET, RESOLVER, 53)
	return _wait_until(lambda: (RESOLVER, 53) in udp_seen)


# --- probes: DROPPED / now CLOSED (must fail to be delivered) -----------------
def probe_udp_other_dropped():
	_udp_send(socket.AF_INET, UDP_OTHER, 9999)
	return not _wait_until(lambda: (UDP_OTHER, 9999) in udp_seen, timeout=1.0)


def probe_udp53_nonresolver_dropped():
	# The DNS-tunnel/exfil leak: udp/53 to ANY non-resolver IP must now drop.
	_udp_send(socket.AF_INET, UDP53_BAD, 53)
	return not _wait_until(lambda: (UDP53_BAD, 53) in udp_seen, timeout=1.0)


def probe_icmp_dropped():
	# ICMP echo to a locally-assigned IP would normally get a kernel reply; the
	# floor drops it at OUTPUT, so ping fails (no unprivileged-ping egress).
	r = subprocess.run(
		["ping", "-c", "1", "-W", "1", ICMP_DST],
		stdout=subprocess.DEVNULL,
		stderr=subprocess.DEVNULL,
	)
	return r.returncode != 0


def probe_raw_l4_dropped():
	# Positive control: proto-132 to loopback (oif lo -> floor accept) MUST be
	# delivered, proving the raw send/recv path works in this env. The real probe:
	# proto-132 to a non-loopback dst MUST be dropped (no SCTP/DCCP/GRE egress).
	_raw_send("127.0.0.1", MARK_CTL + b"\x00" * 8)
	ctl_ok = _wait_until(lambda: any(MARK_CTL in d for d in raw_seen), timeout=2.0)
	_raw_send(RAW_DST, MARK_DROP + b"\x00" * 8)
	dropped = not _wait_until(lambda: any(MARK_DROP in d for d in raw_seen), timeout=1.5)
	return ctl_ok and dropped


def probe_ipv6_tcp_dropped():
	# A bound v6 listener means an unfloored connect WOULD succeed; with the floor
	# the v6 OUTPUT is rejected, so connect raises.
	try:
		s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
		s.settimeout(2.0)
		s.connect((V6_DST, 80))
		s.close()
		return False  # connected -> IPv6 LEAK
	except OSError:
		return True


def probe_ipv6_udp_dropped():
	_udp_send(socket.AF_INET6, V6_DST, 53)
	return not _wait_until(lambda: (V6_DST, 53) in udp_seen, timeout=1.0)


CHECKS = [
	("FORCED-THROUGH  tcp literal-IP  -> shim w/ orig dst", probe_forced_tcp_literal),
	("FORCED-THROUGH  tcp by-name      -> shim w/ orig dst", probe_forced_tcp_name),
	("FORCED-THROUGH  tcp/53           -> shim (not direct)", probe_forced_tcp_port53),
	("CARVE-OUT       tcp enforcer:base-> enforcer (RETURN)", probe_enforcer_carveout),
	("CARVE-OUT       tcp enforcer:other-> shim (redirect)", probe_enforcer_other_port_redirected),
	("ALLOWED         udp/53 -> resolver", probe_udp_resolver_allowed),
	("CLOSED          udp/9999 -> dropped", probe_udp_other_dropped),
	("CLOSED          udp/53 non-resolver -> dropped", probe_udp53_nonresolver_dropped),
	("CLOSED          icmp echo -> dropped", probe_icmp_dropped),
	("CLOSED          raw proto-132 -> dropped", probe_raw_l4_dropped),
	("CLOSED          ipv6 tcp -> dropped", probe_ipv6_tcp_dropped),
	("CLOSED          ipv6 udp -> dropped", probe_ipv6_udp_dropped),
]


def main():
	# Bind every listener first so a leak's packet would have somewhere to land.
	_serve_tcp(socket.AF_INET, SHIM, SHIM_PORT, _shim_sink)
	_serve_tcp(socket.AF_INET, ENFORCER, ENF_PORT, _enf_sink)
	_serve_tcp(socket.AF_INET6, V6_DST, 80, _enf_sink)
	_serve_udp(socket.AF_INET, RESOLVER, 53)
	_serve_udp(socket.AF_INET, UDP_OTHER, 9999)
	_serve_udp(socket.AF_INET, UDP53_BAD, 53)
	_serve_udp(socket.AF_INET6, V6_DST, 53)
	_serve_raw()
	time.sleep(0.3)

	ok = True
	for name, fn in CHECKS:
		try:
			result = fn()
		except Exception as exc:  # a probe blew up -> treat as failure, keep going
			result = False
			name = f"{name}  [exc: {exc!r}]"
		print(f"{'PASS' if result else 'FAIL'}  {name}")
		ok = ok and result

	print("ALL-PASS" if ok else "LEAK-DETECTED")
	sys.exit(0 if ok else 1)


if __name__ == "__main__":
	main()
