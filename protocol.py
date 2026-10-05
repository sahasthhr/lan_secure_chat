"""
protocol.py — Custom Application-Layer Framing & LAN Network Utilities
======================================================================
Computer Networks (CN) Concepts Demonstrated:
1. TCP Stream Framing (Solving TCP Byte-Stream Concatenation/Fragmentation):
   TCP is a stream-oriented protocol (`SOCK_STREAM`) without built-in message boundaries.
   We implement a 4-Byte Network Byte Order (Big-Endian `!I`) Length Header before
   every JSON packet so the receiver knows the exact number of bytes to read.
2. Local Subnet Interface Discovery:
   Determines the active LAN IPv4 address (`192.168.x.x` / `10.x.x.x`) using a
   connectionless UDP routing table lookup without sending traffic on the wire.
"""

import json
import socket
import struct
from typing import Any, Dict, Optional, Tuple

# Default CN Project Ports
TCP_CHAT_PORT = 50000
UDP_DISCOVERY_PORT = 50001
WEB_DASHBOARD_PORT = 8080

# Maximum allowed frame size (16 MB for encrypted file sharing)
MAX_FRAME_SIZE = 16 * 1024 * 1024


def get_lan_ip() -> str:
    """
    Detect the machine's primary LAN IPv4 address (e.g., 192.168.1.x).
    Falls back to 127.0.0.1 if completely disconnected from any network.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Does not actually send any packet; queries OS routing table
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            if ip:
                return ip
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    return "127.0.0.1"


def send_framed_packet(sock: socket.socket, packet_dict: Dict[str, Any]) -> Tuple[int, str]:
    """
    Serialize `packet_dict` to UTF-8 JSON, prepend a 4-byte Big-Endian length header (`!I`),
    and transmit all bytes reliably over `sock` using `sendall()`.

    Returns:
        (total_wire_bytes, header_hex_str)
    """
    payload_bytes = json.dumps(packet_dict, separators=(",", ":")).encode("utf-8")
    payload_len = len(payload_bytes)
    if payload_len > MAX_FRAME_SIZE:
        raise ValueError(f"Packet size {payload_len} exceeds MAX_FRAME_SIZE ({MAX_FRAME_SIZE}).")

    # 4-byte unsigned integer in Network Byte Order (Big-Endian)
    header_bytes = struct.pack("!I", payload_len)
    frame = header_bytes + payload_bytes
    sock.sendall(frame)
    return len(frame), header_bytes.hex()


def recv_exact(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    """
    Read exactly `num_bytes` from a TCP socket, looping until all requested bytes
    arrive or the peer closes the connection (EOF).
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            return None  # Peer closed TCP connection cleanly
        buffer.extend(chunk)
    return bytes(buffer)


def recv_framed_packet(sock: socket.socket) -> Optional[Tuple[Dict[str, Any], int, str]]:
    """
    Read a 4-byte length-prefixed frame from `sock` and parse its UTF-8 JSON payload.

    Returns:
        (packet_dict, total_wire_bytes, header_hex_str) or None on EOF.
    """
    header_bytes = recv_exact(sock, 4)
    if header_bytes is None:
        return None

    (payload_len,) = struct.unpack("!I", header_bytes)
    if payload_len <= 0 or payload_len > MAX_FRAME_SIZE:
        raise ValueError(f"Invalid TCP frame length received: {payload_len} bytes")

    payload_bytes = recv_exact(sock, payload_len)
    if payload_bytes is None:
        return None

    packet_dict = json.loads(payload_bytes.decode("utf-8"))
    return packet_dict, 4 + payload_len, header_bytes.hex()
