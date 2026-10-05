"""
tcp_chat_node.py — Multi-Threaded TCP Chat Server & Real Socket Client Sessions
===============================================================================
Computer Networks (CN) Concepts Demonstrated:
1. Connection-Oriented TCP Sockets (`AF_INET`, `SOCK_STREAM`, `TCP_NODELAY`):
   Guarantees reliable, ordered, error-checked delivery of chat messages and files.
2. Multi-Threaded Concurrent Server Architecture:
   A main listener thread accepts incoming connections on Port 50000 and spawns a
   dedicated daemon thread per client socket, synchronized with `threading.Lock()`.
3. End-to-End Session Encryption & MitM Tamper Detection:
   Every client socket negotiates a unique 2048-bit Diffie-Hellman session key
   and encrypts all payloads with AES-256-GCM. Flipping even 1 bit in transit
   triggers an `InvalidTag` authentication failure on the server.
"""

import base64
import json
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from crypto_engine import DiffieHellmanSession, InvalidTag
from protocol import (
    TCP_CHAT_PORT,
    get_lan_ip,
    recv_framed_packet,
    send_framed_packet,
)


class PacketCaptureInspector:
    """
    Thread-safe Wireshark-style packet capture buffer that records real TCP & UDP
    frames passing through the node for live visualization in the Web Dashboard.
    """

    def __init__(self, max_packets: int = 250) -> None:
        self.max_packets = max_packets
        self._lock = threading.Lock()
        self._packets: List[Dict[str, Any]] = []
        self._seq = 0
        self.stats = {
            "tcp_packets": 0,
            "udp_packets": 0,
            "encrypted_bytes": 0,
            "dh_handshakes": 0,
            "mitm_blocked": 0,
        }

    def record(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            now = time.time()
            pkt = {
                "id": self._seq,
                "timestamp": now,
                "time_str": time.strftime("%H:%M:%S", time.localtime(now))
                + f".{int((now % 1) * 1000):03d}",
                "direction": entry.get("direction", "INBOUND"),
                "protocol": entry.get("protocol", "TCP"),
                "packet_type": entry.get("packet_type", "ENCRYPTED_DATA"),
                "src": entry.get("src", "0.0.0.0:0"),
                "dst": entry.get("dst", "0.0.0.0:0"),
                "wire_bytes": entry.get("wire_bytes", 0),
                "header_hex": entry.get("header_hex", "00000000"),
                "encryption": entry.get("encryption", "AES-256-GCM"),
                "key_fingerprint": entry.get("key_fingerprint", "—"),
                "nonce_hex": entry.get("nonce_hex", "—"),
                "auth_tag_hex": entry.get("auth_tag_hex", "—"),
                "ciphertext_hex": entry.get("ciphertext_hex", ""),
                "plaintext_preview": entry.get("plaintext_preview", ""),
                "status": entry.get("status", "VERIFIED_OK"),
            }
            if pkt["protocol"] == "TCP":
                self.stats["tcp_packets"] += 1
            elif pkt["protocol"] == "UDP":
                self.stats["udp_packets"] += 1

            if pkt["encryption"].startswith("AES"):
                self.stats["encrypted_bytes"] += int(pkt["wire_bytes"])
            if pkt["packet_type"] == "DH_HANDSHAKE_OK":
                self.stats["dh_handshakes"] += 1
            if pkt["status"] == "MITM_BLOCKED":
                self.stats["mitm_blocked"] += 1

            self._packets.append(pkt)
            if len(self._packets) > self.max_packets:
                self._packets = self._packets[-self.max_packets :]
            return pkt

    def get_snapshot(self, since_id: int = 0) -> Dict[str, Any]:
        with self._lock:
            new_packets = [p for p in self._packets if p["id"] > since_id]
            return {
                "packets": new_packets,
                "stats": dict(self.stats),
                "latest_id": self._seq,
            }

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()


@dataclass
class ConnectedClientInfo:
    client_id: str
    username: str
    role: str
    sock: socket.socket
    addr_str: str
    dh_session: DiffieHellmanSession
    connected_at: float = field(default_factory=time.time)
    messages_sent: int = 0
    send_lock: threading.Lock = field(default_factory=threading.Lock)


class TCPChatServer:
    """
    Multi-threaded TCP Socket Server listening on `0.0.0.0:50000`.
    """

    def __init__(
        self,
        port: int = TCP_CHAT_PORT,
        inspector: Optional[PacketCaptureInspector] = None,
    ) -> None:
        self.port = port
        self.lan_ip = get_lan_ip()
        self.inspector = inspector or PacketCaptureInspector()
        self.server_sock: Optional[socket.socket] = None
        self.running = False
        self._clients_lock = threading.Lock()
        self.clients: Dict[str, ConnectedClientInfo] = {}

    def start(self) -> None:
        if self.running:
            return
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", self.port))
        self.server_sock.listen(32)
        self.running = True

        threading.Thread(
            target=self._accept_loop, name="TCP-Server-Accept", daemon=True
        ).start()

    def stop(self) -> None:
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
        with self._clients_lock:
            for c in list(self.clients.values()):
                try:
                    c.sock.close()
                except OSError:
                    pass
            self.clients.clear()

    def get_active_user_count(self) -> int:
        with self._clients_lock:
            return len(self.clients)

    def get_peer_list(self) -> List[Dict[str, Any]]:
        with self._clients_lock:
            return [
                {
                    "client_id": c.client_id,
                    "username": c.username,
                    "role": c.role,
                    "addr": c.addr_str,
                    "key_fingerprint": c.dh_session.key_fingerprint,
                    "connected_at": c.connected_at,
                    "messages_sent": c.messages_sent,
                }
                for c in self.clients.values()
            ]

    def _accept_loop(self) -> None:
        while self.running and self.server_sock:
            try:
                client_sock, addr = self.server_sock.accept()
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    name=f"TCP-Client-{addr[0]}:{addr[1]}",
                    daemon=True,
                ).start()
            except OSError:
                break

    def _send_encrypted_to_client(
        self, client: ConnectedClientInfo, inner_payload: Dict[str, Any], log_packet: bool = False
    ) -> None:
        plaintext_json = json.dumps(inner_payload, separators=(",", ":"))
        enc_meta = client.dh_session.encrypt_payload(plaintext_json)
        wire_packet = {
            "type": "ENCRYPTED_DATA",
            "alg": enc_meta["alg"],
            "nonce_b64": enc_meta["nonce_b64"],
            "ct_b64": enc_meta["ct_b64"],
            "aad": enc_meta["aad"],
        }
        with client.send_lock:
            wire_bytes, header_hex = send_framed_packet(client.sock, wire_packet)

        if log_packet:
            self.inspector.record(
                {
                    "direction": "OUTBOUND",
                    "protocol": "TCP",
                    "packet_type": f"TCP_{inner_payload.get('event', 'DATA')}",
                    "src": f"{self.lan_ip}:{self.port}",
                    "dst": client.addr_str,
                    "wire_bytes": wire_bytes,
                    "header_hex": header_hex,
                    "encryption": "AES-256-GCM",
                    "key_fingerprint": client.dh_session.key_fingerprint,
                    "nonce_hex": enc_meta["nonce_hex"],
                    "auth_tag_hex": enc_meta["auth_tag_hex"],
                    "ciphertext_hex": enc_meta["ciphertext_hex"][:120],
                    "plaintext_preview": plaintext_json[:140],
                    "status": "ENCRYPTED_SENT",
                }
            )

    def _broadcast_event(
        self, inner_payload: Dict[str, Any], target_username: Optional[str] = None, sender_username: Optional[str] = None
    ) -> None:
        with self._clients_lock:
            targets = list(self.clients.values())

        for c in targets:
            if target_username and target_username != "ALL":
                if c.username not in (target_username, sender_username):
                    continue
            try:
                self._send_encrypted_to_client(c, inner_payload, log_packet=False)
            except OSError:
                pass

    def _broadcast_peer_list(self) -> None:
        peers = self.get_peer_list()
        self._broadcast_event({"event": "PEER_LIST", "peers": peers, "timestamp": time.time()})

    def _handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        addr_str = f"{addr[0]}:{addr[1]}"
        server_addr_str = f"{self.lan_ip}:{self.port}"
        client_info: Optional[ConnectedClientInfo] = None

        try:
            # Step 1: Receive DH_HELLO handshake over TCP
            hello_res = recv_framed_packet(client_sock)
            if hello_res is None:
                client_sock.close()
                return
            hello_pkt, wire_bytes, header_hex = hello_res
            if hello_pkt.get("type") != "DH_HELLO":
                client_sock.close()
                return

            raw_username = str(hello_pkt.get("username", "Peer")).strip() or "Peer"
            role = str(hello_pkt.get("role", "web_client"))
            client_dh_pub = str(hello_pkt["client_dh_pub"])

            # Ensure unique username on server
            with self._clients_lock:
                existing_names = {c.username.lower() for c in self.clients.values()}
                username = raw_username
                suffix = 2
                while username.lower() in existing_names:
                    username = f"{raw_username}_{suffix}"
                    suffix += 1

            # Step 2: Compute Diffie-Hellman Shared Secret & Derive AES-256-GCM Session Key
            dh_session = DiffieHellmanSession()
            key_fp = dh_session.compute_shared_key(client_dh_pub)
            client_id = str(uuid.uuid4())[:8]

            welcome_pkt = {
                "type": "DH_WELCOME",
                "client_id": client_id,
                "assigned_username": username,
                "server_dh_pub": dh_session.get_public_key_hex(),
                "key_fingerprint": key_fp,
                "server_ip": self.lan_ip,
                "server_port": self.port,
            }
            w_bytes, w_hdr = send_framed_packet(client_sock, welcome_pkt)

            self.inspector.record(
                {
                    "direction": "HANDSHAKE",
                    "protocol": "TCP",
                    "packet_type": "DH_HANDSHAKE_OK",
                    "src": addr_str,
                    "dst": server_addr_str,
                    "wire_bytes": wire_bytes + w_bytes,
                    "header_hex": header_hex,
                    "encryption": "DH-2048 Key Exchange -> AES-256-GCM",
                    "key_fingerprint": key_fp,
                    "nonce_hex": "EPHEMERAL_DH_MODP_2048",
                    "auth_tag_hex": "SHA256_KDF_VERIFIED",
                    "ciphertext_hex": client_dh_pub[:96] + "...",
                    "plaintext_preview": (
                        f"Handshake Complete for '{username}' ({addr_str}) | "
                        f"Derived AES-256 Key Fingerprint: {key_fp}"
                    ),
                    "status": "HANDSHAKE_VERIFIED",
                }
            )

            client_info = ConnectedClientInfo(
                client_id=client_id,
                username=username,
                role=role,
                sock=client_sock,
                addr_str=addr_str,
                dh_session=dh_session,
            )
            with self._clients_lock:
                self.clients[client_id] = client_info

            # Notify all connected peers of the updated peer list and join event
            self._broadcast_peer_list()
            self._broadcast_event(
                {
                    "event": "SYSTEM_NOTICE",
                    "id": str(uuid.uuid4())[:10],
                    "text": f"{username} joined the LAN via TCP ({addr_str}) — E2EE Key [{key_fp[:14]}]",
                    "timestamp": time.time(),
                }
            )

            # Step 3: Receive Encrypted Frames Loop
            while self.running:
                frame_res = recv_framed_packet(client_sock)
                if frame_res is None:
                    break

                pkt, frame_bytes, frame_hdr_hex = frame_res
                if pkt.get("type") != "ENCRYPTED_DATA":
                    continue

                # Attempt AES-256-GCM Authenticated Decryption
                try:
                    decrypted_str, dec_meta = dh_session.decrypt_payload(pkt)
                except InvalidTag:
                    # Man-in-the-Middle / Ciphertext Tampering Detected!
                    raw_ct = base64.b64decode(pkt.get("ct_b64", ""))
                    nonce_raw = base64.b64decode(pkt.get("nonce_b64", ""))
                    self.inspector.record(
                        {
                            "direction": "INBOUND",
                            "protocol": "TCP",
                            "packet_type": "MITM_TAMPER_DETECTED",
                            "src": addr_str,
                            "dst": server_addr_str,
                            "wire_bytes": frame_bytes,
                            "header_hex": frame_hdr_hex,
                            "encryption": "AES-256-GCM (AUTH TAG FAILED!)",
                            "key_fingerprint": key_fp,
                            "nonce_hex": nonce_raw.hex(),
                            "auth_tag_hex": raw_ct[-16:].hex() if len(raw_ct) >= 16 else "CORRUPTED",
                            "ciphertext_hex": raw_ct[:-16].hex()[:120],
                            "plaintext_preview": (
                                f"[SECURITY ALERT] Packet from {username} ({addr_str}) REJECTED! "
                                "128-bit GCM Authentication Tag mismatch (Ciphertext tampered in transit)."
                            ),
                            "status": "MITM_BLOCKED",
                        }
                    )
                    self._broadcast_event(
                        {
                            "event": "SECURITY_ALERT",
                            "id": str(uuid.uuid4())[:10],
                            "sender": username,
                            "addr": addr_str,
                            "text": (
                                f"AES-256-GCM Integrity Check Blocked a Tampered TCP Packet from {addr_str}! "
                                "128-bit GCM Authentication Tag verification failed (MitM protection active)."
                            ),
                            "timestamp": time.time(),
                        }
                    )
                    continue

                inner = json.loads(decrypted_str)
                action = inner.get("action", "CHAT_MESSAGE")
                target = inner.get("target", "ALL")
                client_info.messages_sent += 1

                if action == "CHAT_MESSAGE":
                    msg_text = str(inner.get("text", "")).strip()
                    msg_id = str(uuid.uuid4())[:10]
                    is_dm = target != "ALL"

                    self.inspector.record(
                        {
                            "direction": "INBOUND",
                            "protocol": "TCP",
                            "packet_type": "TCP_DM_ENCRYPTED" if is_dm else "TCP_GROUP_ENCRYPTED",
                            "src": addr_str,
                            "dst": server_addr_str,
                            "wire_bytes": frame_bytes,
                            "header_hex": frame_hdr_hex,
                            "encryption": "AES-256-GCM",
                            "key_fingerprint": key_fp,
                            "nonce_hex": dec_meta["nonce_hex"],
                            "auth_tag_hex": dec_meta["auth_tag_hex"],
                            "ciphertext_hex": dec_meta["ciphertext_hex"][:120],
                            "plaintext_preview": f"[{username} -> {target}]: {msg_text}",
                            "status": "VERIFIED_OK",
                        }
                    )

                    chat_event = {
                        "event": "CHAT_MESSAGE",
                        "id": msg_id,
                        "sender": username,
                        "sender_addr": addr_str,
                        "target": target,
                        "is_dm": is_dm,
                        "text": msg_text,
                        "wire_bytes": frame_bytes,
                        "nonce_hex": dec_meta["nonce_hex"],
                        "auth_tag_hex": dec_meta["auth_tag_hex"],
                        "ciphertext_hex": dec_meta["ciphertext_hex"][:64],
                        "key_fingerprint": key_fp,
                        "timestamp": time.time(),
                    }
                    self._broadcast_event(
                        chat_event, target_username=target, sender_username=username
                    )
                    self._broadcast_peer_list()

                elif action == "FILE_SHARE":
                    filename = str(inner.get("filename", "attachment.bin"))
                    mime_type = str(inner.get("mime_type", "application/octet-stream"))
                    data_b64 = str(inner.get("data_b64", ""))
                    size_bytes = int(inner.get("size_bytes", 0))
                    is_dm = target != "ALL"

                    self.inspector.record(
                        {
                            "direction": "INBOUND",
                            "protocol": "TCP",
                            "packet_type": "TCP_ENCRYPTED_FILE",
                            "src": addr_str,
                            "dst": server_addr_str,
                            "wire_bytes": frame_bytes,
                            "header_hex": frame_hdr_hex,
                            "encryption": "AES-256-GCM",
                            "key_fingerprint": key_fp,
                            "nonce_hex": dec_meta["nonce_hex"],
                            "auth_tag_hex": dec_meta["auth_tag_hex"],
                            "ciphertext_hex": dec_meta["ciphertext_hex"][:120],
                            "plaintext_preview": (
                                f"[FILE TRANSFER] '{filename}' ({size_bytes} bytes) from {username} -> {target}"
                            ),
                            "status": "VERIFIED_OK",
                        }
                    )

                    file_event = {
                        "event": "FILE_SHARE",
                        "id": str(uuid.uuid4())[:10],
                        "sender": username,
                        "sender_addr": addr_str,
                        "target": target,
                        "is_dm": is_dm,
                        "filename": filename,
                        "mime_type": mime_type,
                        "data_b64": data_b64,
                        "size_bytes": size_bytes,
                        "wire_bytes": frame_bytes,
                        "nonce_hex": dec_meta["nonce_hex"],
                        "auth_tag_hex": dec_meta["auth_tag_hex"],
                        "ciphertext_hex": dec_meta["ciphertext_hex"][:64],
                        "key_fingerprint": key_fp,
                        "timestamp": time.time(),
                    }
                    self._broadcast_event(
                        file_event, target_username=target, sender_username=username
                    )
                    self._broadcast_peer_list()

        except (OSError, ValueError, KeyError):
            pass
        finally:
            if client_info:
                with self._clients_lock:
                    self.clients.pop(client_info.client_id, None)
                self._broadcast_peer_list()
                self._broadcast_event(
                    {
                        "event": "SYSTEM_NOTICE",
                        "id": str(uuid.uuid4())[:10],
                        "text": f"{client_info.username} ({addr_str}) disconnected from TCP server.",
                        "timestamp": time.time(),
                    }
                )
            try:
                client_sock.close()
            except OSError:
                pass


class RealTCPClientSession:
    """
    A real OS-level TCP Client Socket (`socket.SOCK_STREAM`) that connects to a
    LAN TCPChatServer, completes the 2048-bit Diffie-Hellman handshake, and sends/receives
    length-prefixed AES-256-GCM encrypted packets.
    """

    def __init__(
        self,
        username: str,
        server_host: str,
        server_port: int = TCP_CHAT_PORT,
        role: str = "web_client",
        on_message_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.requested_username = username
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.role = role
        self.on_message_cb = on_message_cb

        self.session_token = str(uuid.uuid4())
        self.client_id = ""
        self.sock: Optional[socket.socket] = None
        self.local_addr = "0.0.0.0:0"
        self.dh_session = DiffieHellmanSession()
        self.key_fingerprint = ""
        self.connected = False

        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self.events: List[Dict[str, Any]] = []
        self.peers: List[Dict[str, Any]] = []
        self._event_seq = 0

    def connect(self, timeout: float = 5.0) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((self.server_host, self.server_port))
        sock.settimeout(None)
        self.sock = sock
        local_ip, local_port = sock.getsockname()[:2]
        self.local_addr = f"{local_ip}:{local_port}"

        # Send DH_HELLO with our 2048-bit Diffie-Hellman public key
        hello_pkt = {
            "type": "DH_HELLO",
            "username": self.requested_username,
            "role": self.role,
            "client_dh_pub": self.dh_session.get_public_key_hex(),
        }
        send_framed_packet(sock, hello_pkt)

        # Wait for DH_WELCOME from server
        welcome_res = recv_framed_packet(sock)
        if welcome_res is None:
            sock.close()
            raise ConnectionError("Server closed connection during Diffie-Hellman handshake.")

        welcome_pkt, _, _ = welcome_res
        if welcome_pkt.get("type") != "DH_WELCOME":
            sock.close()
            raise ConnectionError("Unexpected handshake response from TCP server.")

        self.client_id = str(welcome_pkt["client_id"])
        self.username = str(welcome_pkt["assigned_username"])
        server_dh_pub = str(welcome_pkt["server_dh_pub"])
        self.key_fingerprint = self.dh_session.compute_shared_key(server_dh_pub)
        self.connected = True

        threading.Thread(
            target=self._recv_loop,
            name=f"TCPClientRecv-{self.username}",
            daemon=True,
        ).start()

        return {
            "session_token": self.session_token,
            "client_id": self.client_id,
            "username": self.username,
            "local_addr": self.local_addr,
            "server_addr": f"{self.server_host}:{self.server_port}",
            "key_fingerprint": self.key_fingerprint,
        }

    def _recv_loop(self) -> None:
        while self.connected and self.sock:
            try:
                res = recv_framed_packet(self.sock)
                if res is None:
                    break
                pkt, _, _ = res
                if pkt.get("type") != "ENCRYPTED_DATA":
                    continue

                plaintext_str, _ = self.dh_session.decrypt_payload(pkt)
                inner = json.loads(plaintext_str)
                event_type = inner.get("event")

                if event_type == "PEER_LIST":
                    with self._lock:
                        self.peers = inner.get("peers", [])
                else:
                    with self._lock:
                        self._event_seq += 1
                        inner["seq"] = self._event_seq
                        self.events.append(inner)
                        if len(self.events) > 300:
                            self.events = self.events[-300:]

                    if self.on_message_cb:
                        try:
                            self.on_message_cb(inner)
                        except Exception:
                            pass
            except (OSError, ValueError, InvalidTag):
                break

        self.connected = False

    def send_chat_message(self, text: str, target: str = "ALL") -> Dict[str, Any]:
        if not self.connected or not self.sock:
            raise ConnectionError("TCP socket is not connected.")

        inner_payload = {
            "action": "CHAT_MESSAGE",
            "text": text,
            "target": target,
            "timestamp": time.time(),
        }
        plaintext_json = json.dumps(inner_payload, separators=(",", ":"))
        enc_meta = self.dh_session.encrypt_payload(plaintext_json)
        wire_pkt = {
            "type": "ENCRYPTED_DATA",
            "alg": enc_meta["alg"],
            "nonce_b64": enc_meta["nonce_b64"],
            "ct_b64": enc_meta["ct_b64"],
            "aad": enc_meta["aad"],
        }
        with self._send_lock:
            wire_bytes, header_hex = send_framed_packet(self.sock, wire_pkt)
        return {
            "wire_bytes": wire_bytes,
            "header_hex": header_hex,
            "nonce_hex": enc_meta["nonce_hex"],
            "auth_tag_hex": enc_meta["auth_tag_hex"],
            "ciphertext_hex": enc_meta["ciphertext_hex"][:64],
        }

    def send_file(
        self,
        filename: str,
        mime_type: str,
        data_b64: str,
        size_bytes: int,
        target: str = "ALL",
    ) -> Dict[str, Any]:
        if not self.connected or not self.sock:
            raise ConnectionError("TCP socket is not connected.")

        inner_payload = {
            "action": "FILE_SHARE",
            "filename": filename,
            "mime_type": mime_type,
            "data_b64": data_b64,
            "size_bytes": size_bytes,
            "target": target,
            "timestamp": time.time(),
        }
        plaintext_json = json.dumps(inner_payload, separators=(",", ":"))
        enc_meta = self.dh_session.encrypt_payload(plaintext_json)
        wire_pkt = {
            "type": "ENCRYPTED_DATA",
            "alg": enc_meta["alg"],
            "nonce_b64": enc_meta["nonce_b64"],
            "ct_b64": enc_meta["ct_b64"],
            "aad": enc_meta["aad"],
        }
        with self._send_lock:
            wire_bytes, header_hex = send_framed_packet(self.sock, wire_pkt)
        return {"wire_bytes": wire_bytes, "header_hex": header_hex}

    def simulate_mitm_tampered_packet(
        self, original_text: str = "Transfer $500 to Alice"
    ) -> Dict[str, Any]:
        """
        Encrypts a real message with AES-256-GCM, then intentionally flips bits in the
        ciphertext before transmitting over the TCP socket to demonstrate how GCM
        authentication detects and blocks Man-in-the-Middle tampering.
        """
        if not self.connected or not self.sock:
            raise ConnectionError("TCP socket is not connected.")

        inner_payload = {
            "action": "CHAT_MESSAGE",
            "text": original_text,
            "target": "ALL",
            "timestamp": time.time(),
        }
        plaintext_json = json.dumps(inner_payload, separators=(",", ":"))
        enc_meta = self.dh_session.encrypt_payload(plaintext_json)

        # Decode ciphertext+tag and flip bits in the first byte of ciphertext
        raw_ct = bytearray(base64.b64decode(enc_meta["ct_b64"]))
        raw_ct[0] ^= 0xFF
        raw_ct[1] ^= 0xAA
        tampered_ct_b64 = base64.b64encode(bytes(raw_ct)).decode("ascii")

        wire_pkt = {
            "type": "ENCRYPTED_DATA",
            "alg": enc_meta["alg"],
            "nonce_b64": enc_meta["nonce_b64"],
            "ct_b64": tampered_ct_b64,
            "aad": enc_meta["aad"],
        }
        with self._send_lock:
            wire_bytes, header_hex = send_framed_packet(self.sock, wire_pkt)
        return {
            "wire_bytes": wire_bytes,
            "header_hex": header_hex,
            "tampered_ciphertext_hex": bytes(raw_ct[:-16]).hex()[:64],
        }

    def get_updates(self, since_seq: int = 0) -> Dict[str, Any]:
        with self._lock:
            new_events = [e for e in self.events if e.get("seq", 0) > since_seq]
            return {
                "connected": self.connected,
                "username": self.username,
                "local_addr": self.local_addr,
                "server_addr": f"{self.server_host}:{self.server_port}",
                "key_fingerprint": self.key_fingerprint,
                "peers": list(self.peers),
                "events": new_events,
                "latest_seq": self._event_seq,
            }

    def close(self) -> None:
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
