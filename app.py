"""
app.py — Main Entrypoint: TCP Server + UDP Broadcast Discovery + Web Dashboard
==============================================================================
Starts three services in one unified process:
1. Multi-Threaded TCP Chat Server on `0.0.0.0:50000` (`SOCK_STREAM`)
2. UDP Broadcast Discovery Service on `0.0.0.0:50001` (`SOCK_DGRAM`, `SO_BROADCAST`)
3. Modern Web Dashboard & REST Bridge on `0.0.0.0:8080`

Every user joining from the Web Dashboard opens a REAL OS-level TCP Client Socket
(`socket.AF_INET, socket.SOCK_STREAM`) that negotiates a 2048-bit Diffie-Hellman
key exchange and transmits length-prefixed AES-256-GCM encrypted packets.
"""

import json
import mimetypes
import os
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from protocol import (
    TCP_CHAT_PORT,
    UDP_DISCOVERY_PORT,
    WEB_DASHBOARD_PORT,
    get_lan_ip,
)
from tcp_chat_node import PacketCaptureInspector, RealTCPClientSession, TCPChatServer
from udp_discovery import UDPDiscoveryService

STATIC_DIR = Path(__file__).parent / "static"


class ApplicationState:
    def __init__(self) -> None:
        self.lan_ip = get_lan_ip()
        self.hostname = socket.gethostname()
        self.inspector = PacketCaptureInspector(max_packets=300)
        self.tcp_server = TCPChatServer(port=TCP_CHAT_PORT, inspector=self.inspector)
        self.udp_service = UDPDiscoveryService(
            node_name=f"LAN-Hub ({self.hostname})",
            tcp_port=TCP_CHAT_PORT,
            udp_port=UDP_DISCOVERY_PORT,
            user_count_fn=self.tcp_server.get_active_user_count,
            packet_logger_fn=self.inspector.record,
        )
        self._sessions_lock = threading.Lock()
        self.sessions: Dict[str, RealTCPClientSession] = {}
        self.bot_peers: Dict[str, RealTCPClientSession] = {}
        self._bot_counter = 0

    def start_all(self) -> None:
        self.tcp_server.start()
        self.udp_service.start()
        # Spawn a default real-socket LAN peer so single-laptop demos immediately show active E2EE traffic
        self.spawn_bot_peer("Aarav (Lab PC)", send_greeting=True)

    def spawn_bot_peer(self, requested_name: str = "", send_greeting: bool = True) -> Dict[str, Any]:
        with self._sessions_lock:
            self._bot_counter += 1
            name = requested_name.strip() or f"Friend_PC_{self._bot_counter}"

        bot_ref: Dict[str, RealTCPClientSession] = {}

        def on_bot_receive(event: Dict[str, Any]) -> None:
            if event.get("event") != "CHAT_MESSAGE":
                return
            sender = event.get("sender", "")
            bot_client = bot_ref.get("client")
            if not bot_client or sender == bot_client.username:
                return
            # Avoid infinite bot-to-bot loops
            if sender in self.bot_peers:
                return

            text = str(event.get("text", "")).strip()
            target = event.get("target", "ALL")
            is_dm_to_bot = target == bot_client.username
            is_mention = f"@{bot_client.username.lower()}" in text.lower()

            # Reply automatically to DMs, @mentions, or when the bot is the default friend
            if is_dm_to_bot or is_mention or bot_client.username == "Aarav (Lab PC)":
                def delayed_reply() -> None:
                    time.sleep(0.6)
                    if not bot_client.connected:
                        return
                    reply_target = sender if is_dm_to_bot else "ALL"
                    if is_dm_to_bot:
                        reply_text = f"Hey {sender}! Got your private encrypted message: \"{text}\" 🔒"
                    else:
                        reply_text = f"Hi {sender}! Received your message on the LAN group chat 👍"
                    try:
                        bot_client.send_chat_message(reply_text, target=reply_target)
                    except OSError:
                        pass

                threading.Thread(target=delayed_reply, daemon=True).start()

        bot_session = RealTCPClientSession(
            username=name,
            server_host=self.lan_ip,
            server_port=TCP_CHAT_PORT,
            role="lan_peer",
            on_message_cb=on_bot_receive,
        )
        bot_ref["client"] = bot_session
        info = bot_session.connect()
        with self._sessions_lock:
            self.bot_peers[bot_session.username] = bot_session

        if send_greeting:
            bot_session.send_chat_message(
                f"Hey everyone! I'm online on the LAN Wi-Fi 👋",
                target="ALL",
            )
        return info


STATE = ApplicationState()


class DashboardHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy per-poll HTTP logs so terminal stays clean
        return

    def _send_json(self, data: Dict[str, Any], status: int = HTTPStatus.OK) -> None:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/node-info":
            self._send_json(
                {
                    "lan_ip": STATE.lan_ip,
                    "hostname": STATE.hostname,
                    "tcp_port": TCP_CHAT_PORT,
                    "udp_port": UDP_DISCOVERY_PORT,
                    "web_port": WEB_DASHBOARD_PORT,
                    "discovered_nodes": STATE.udp_service.get_discovered_nodes(),
                    "peers": STATE.tcp_server.get_peer_list(),
                    "stats": STATE.inspector.stats,
                }
            )
            return

        if path == "/api/poll":
            qs = parse_qs(parsed.query)
            token = (qs.get("token") or [""])[0]
            since_seq = int((qs.get("since_seq") or ["0"])[0])
            since_pkt = int((qs.get("since_pkt") or ["0"])[0])

            inspector_snap = STATE.inspector.get_snapshot(since_id=since_pkt)
            discovered = STATE.udp_service.get_discovered_nodes()

            with STATE._sessions_lock:
                session = STATE.sessions.get(token)

            if not session:
                self._send_json(
                    {
                        "authenticated": False,
                        "discovered_nodes": discovered,
                        "peers": STATE.tcp_server.get_peer_list(),
                        "inspector": inspector_snap,
                    }
                )
                return

            client_updates = session.get_updates(since_seq=since_seq)
            self._send_json(
                {
                    "authenticated": True,
                    "client": client_updates,
                    "discovered_nodes": discovered,
                    "inspector": inspector_snap,
                }
            )
            return

        # Serve static files
        if path == "/" or path == "":
            file_path = STATIC_DIR / "index.html"
        else:
            rel = path.lstrip("/")
            file_path = (STATIC_DIR / rel).resolve()
            if not str(file_path).startswith(str(STATIC_DIR.resolve())):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

        if not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        mime, _ = mimetypes.guess_type(str(file_path))
        content = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime or 'text/plain'}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_json({"error": f"Invalid JSON: {exc}"}, status=HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/connect":
            username = str(body.get("username", "")).strip() or "Student_Peer"
            server_host = str(body.get("server_host", "")).strip() or STATE.lan_ip
            server_port = int(body.get("server_port", TCP_CHAT_PORT))

            try:
                client = RealTCPClientSession(
                    username=username,
                    server_host=server_host,
                    server_port=server_port,
                    role="web_client",
                )
                info = client.connect()
                with STATE._sessions_lock:
                    STATE.sessions[client.session_token] = client
                self._send_json({"ok": True, "session": info})
            except Exception as exc:
                self._send_json(
                    {"ok": False, "error": f"TCP Connection Failed: {exc}"},
                    status=HTTPStatus.BAD_GATEWAY,
                )
            return

        if path == "/api/send":
            token = str(body.get("token", ""))
            text = str(body.get("text", "")).strip()
            target = str(body.get("target", "ALL")).strip() or "ALL"

            with STATE._sessions_lock:
                session = STATE.sessions.get(token)
            if not session or not session.connected:
                self._send_json(
                    {"ok": False, "error": "Active TCP session not found."},
                    status=HTTPStatus.UNAUTHORIZED,
                )
                return
            if not text:
                self._send_json(
                    {"ok": False, "error": "Message cannot be empty."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            meta = session.send_chat_message(text=text, target=target)
            self._send_json({"ok": True, "packet": meta})
            return

        if path == "/api/send-file":
            token = str(body.get("token", ""))
            filename = str(body.get("filename", "document.txt"))
            mime_type = str(body.get("mime_type", "application/octet-stream"))
            data_b64 = str(body.get("data_b64", ""))
            size_bytes = int(body.get("size_bytes", 0))
            target = str(body.get("target", "ALL")).strip() or "ALL"

            with STATE._sessions_lock:
                session = STATE.sessions.get(token)
            if not session or not session.connected:
                self._send_json(
                    {"ok": False, "error": "Active TCP session not found."},
                    status=HTTPStatus.UNAUTHORIZED,
                )
                return

            meta = session.send_file(
                filename=filename,
                mime_type=mime_type,
                data_b64=data_b64,
                size_bytes=size_bytes,
                target=target,
            )
            self._send_json({"ok": True, "packet": meta})
            return

        if path == "/api/udp-beacon":
            beacon = STATE.udp_service.send_beacon_now(log_to_inspector=True)
            self._send_json(
                {
                    "ok": True,
                    "beacon": beacon,
                    "discovered_nodes": STATE.udp_service.get_discovered_nodes(),
                }
            )
            return

        if path == "/api/simulate-mitm":
            token = str(body.get("token", ""))
            with STATE._sessions_lock:
                session = STATE.sessions.get(token)
            if not session or not session.connected:
                self._send_json(
                    {"ok": False, "error": "Connect your TCP session first."},
                    status=HTTPStatus.UNAUTHORIZED,
                )
                return

            res = session.simulate_mitm_tampered_packet(
                original_text=str(
                    body.get("text", "CONFIDENTIAL: Admin Password = 9941")
                )
            )
            self._send_json({"ok": True, "tampered": res})
            return

        if path == "/api/spawn-peer":
            peer_name = str(body.get("username", "")).strip()
            info = STATE.spawn_bot_peer(requested_name=peer_name, send_greeting=True)
            self._send_json({"ok": True, "peer": info})
            return

        if path == "/api/clear-inspector":
            STATE.inspector.clear()
            self._send_json({"ok": True})
            return

        self.send_error(HTTPStatus.NOT_FOUND)


def main() -> None:
    STATE.start_all()
    http_server = ThreadingHTTPServer(("0.0.0.0", WEB_DASHBOARD_PORT), DashboardHTTPHandler)

    print("=" * 74)
    print("  LAN-BASED SECURE CHAT APPLICATION — COMPUTER NETWORKS PROJECT")
    print("=" * 74)
    print(f"  [+] Detected Primary LAN IP     : {STATE.lan_ip}")
    print(f"  [+] TCP Secure Chat Server      : {STATE.lan_ip}:{TCP_CHAT_PORT} (SOCK_STREAM, DH-2048 + AES-256-GCM)")
    print(f"  [+] UDP Broadcast Discovery     : 255.255.255.255:{UDP_DISCOVERY_PORT} (SOCK_DGRAM, SO_BROADCAST)")
    print(f"  [+] Web Dashboard (This PC)     : http://localhost:{WEB_DASHBOARD_PORT}")
    print(f"  [+] Web Dashboard (Other PCs)   : http://{STATE.lan_ip}:{WEB_DASHBOARD_PORT}")
    print("=" * 74)

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down TCP/UDP sockets...")
        STATE.udp_service.stop()
        STATE.tcp_server.stop()
        http_server.server_close()


if __name__ == "__main__":
    main()
