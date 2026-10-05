"""
udp_discovery.py — Connectionless UDP Broadcast Peer Discovery Service
======================================================================
Computer Networks (CN) Concepts Demonstrated:
1. UDP (`SOCK_DGRAM`) Connectionless Transport:
   Unlike TCP, UDP does not require a 3-way handshake and supports 1-to-Many
   subnet broadcasting (`SO_BROADCAST`).
2. Limited Broadcast (`255.255.255.255`) & Directed Subnet Broadcast (`x.x.x.255`):
   Periodically announces this node's hostname, LAN IP, and active TCP Chat Port
   so any peer on the same Wi-Fi/Ethernet LAN automatically discovers it without
   typing IP addresses manually.
"""

import json
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from protocol import TCP_CHAT_PORT, UDP_DISCOVERY_PORT, get_lan_ip

BEACON_MAGIC = "LAN_SECURE_CHAT_BEACON_V1"


class UDPDiscoveryService:
    """
    Runs two background daemon threads:
    1. UDP Broadcast Listener on `0.0.0.0:50001`
    2. Periodic UDP Beacon Broadcaster to `<broadcast>:50001`
    """

    def __init__(
        self,
        node_name: str,
        tcp_port: int = TCP_CHAT_PORT,
        udp_port: int = UDP_DISCOVERY_PORT,
        user_count_fn: Optional[Callable[[], int]] = None,
        packet_logger_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.node_name = node_name
        self.lan_ip = get_lan_ip()
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.user_count_fn = user_count_fn or (lambda: 0)
        self.packet_logger_fn = packet_logger_fn

        self.running = False
        self._lock = threading.Lock()
        self.discovered_nodes: Dict[str, Dict[str, Any]] = {}
        self.beacon_seq = 0

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        threading.Thread(
            target=self._listen_loop, name="UDP-Discovery-Listener", daemon=True
        ).start()
        threading.Thread(
            target=self._broadcast_loop, name="UDP-Discovery-Broadcaster", daemon=True
        ).start()
        # Send an immediate initial beacon
        self.send_beacon_now(log_to_inspector=True)

    def stop(self) -> None:
        self.running = False

    def _get_broadcast_targets(self) -> List[str]:
        targets = ["255.255.255.255"]
        parts = self.lan_ip.split(".")
        if len(parts) == 4 and parts[0] != "127":
            subnet_bcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            if subnet_bcast not in targets:
                targets.append(subnet_bcast)
        return targets

    def send_beacon_now(self, log_to_inspector: bool = True) -> Dict[str, Any]:
        """
        Broadcast a single UDP discovery datagram across the LAN subnet immediately.
        Can also be triggered manually from the Web Dashboard for CN Viva demos.
        """
        self.lan_ip = get_lan_ip()
        self.beacon_seq += 1
        beacon_payload = {
            "magic": BEACON_MAGIC,
            "seq": self.beacon_seq,
            "node_name": self.node_name,
            "hostname": socket.gethostname(),
            "lan_ip": self.lan_ip,
            "tcp_port": self.tcp_port,
            "active_users": self.user_count_fn(),
            "timestamp": time.time(),
        }
        raw_bytes = json.dumps(beacon_payload, separators=(",", ":")).encode("utf-8")

        targets = self._get_broadcast_targets()
        sent_target = targets[-1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(0.5)
                for target_ip in targets:
                    try:
                        s.sendto(raw_bytes, (target_ip, self.udp_port))
                        sent_target = target_ip
                    except OSError:
                        pass
                # Also send to loopback so local listeners always receive it even if OS firewall blocks broadcast
                try:
                    s.sendto(raw_bytes, ("127.0.0.1", self.udp_port))
                except OSError:
                    pass
        except OSError:
            pass

        if log_to_inspector and self.packet_logger_fn:
            self.packet_logger_fn(
                {
                    "direction": "OUTBOUND",
                    "protocol": "UDP",
                    "packet_type": "UDP_BROADCAST_BEACON",
                    "src": f"{self.lan_ip}:{self.udp_port}",
                    "dst": f"{sent_target}:{self.udp_port}",
                    "wire_bytes": len(raw_bytes),
                    "header_hex": "UDP-DGRAM (8B Hdr)",
                    "encryption": "NONE (Public LAN Discovery Beacon)",
                    "ciphertext_hex": raw_bytes.hex()[:96],
                    "plaintext_preview": (
                        f"BEACON #{self.beacon_seq} | Host: {self.node_name} "
                        f"({self.lan_ip}:{self.tcp_port}) | Active Users: {beacon_payload['active_users']}"
                    ),
                    "status": "BROADCAST_OK",
                }
            )
        return beacon_payload

    def _broadcast_loop(self) -> None:
        while self.running:
            time.sleep(12.0)
            if not self.running:
                break
            # Periodic background beacon (don't flood inspector unless requested)
            self.send_beacon_now(log_to_inspector=False)

    def _listen_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.udp_port))
        except OSError:
            sock.close()
            return

        sock.settimeout(1.0)
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                msg = json.loads(data.decode("utf-8"))
                if msg.get("magic") != BEACON_MAGIC:
                    continue

                sender_ip = msg.get("lan_ip") or addr[0]
                tcp_port = int(msg.get("tcp_port", TCP_CHAT_PORT))
                node_key = f"{sender_ip}:{tcp_port}"
                is_self = sender_ip in (self.lan_ip, "127.0.0.1") and tcp_port == self.tcp_port

                with self._lock:
                    is_new = node_key not in self.discovered_nodes
                    self.discovered_nodes[node_key] = {
                        "node_key": node_key,
                        "node_name": msg.get("node_name", "LAN-Host"),
                        "hostname": msg.get("hostname", "unknown"),
                        "lan_ip": sender_ip,
                        "tcp_port": tcp_port,
                        "active_users": msg.get("active_users", 0),
                        "is_local_hub": is_self,
                        "last_seen": time.time(),
                        "seq": msg.get("seq", 1),
                    }

                if is_new and not is_self and self.packet_logger_fn:
                    self.packet_logger_fn(
                        {
                            "direction": "INBOUND",
                            "protocol": "UDP",
                            "packet_type": "UDP_PEER_DISCOVERED",
                            "src": f"{addr[0]}:{addr[1]}",
                            "dst": f"255.255.255.255:{self.udp_port}",
                            "wire_bytes": len(data),
                            "header_hex": "UDP-DGRAM (8B Hdr)",
                            "encryption": "NONE (Public Discovery)",
                            "ciphertext_hex": data.hex()[:96],
                            "plaintext_preview": f"Discovered LAN Host '{msg.get('node_name')}' at {node_key}",
                            "status": "DISCOVERED",
                        }
                    )
            except (ValueError, KeyError):
                continue

        sock.close()

    def get_discovered_nodes(self) -> List[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            # Prune stale nodes older than 45 seconds (except local hub)
            stale = [
                k
                for k, v in self.discovered_nodes.items()
                if not v.get("is_local_hub") and (now - v["last_seen"] > 45.0)
            ]
            for k in stale:
                del self.discovered_nodes[k]
            return sorted(
                self.discovered_nodes.values(),
                key=lambda x: (not x.get("is_local_hub", False), x["node_key"]),
            )
