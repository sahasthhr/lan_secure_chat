"""
cli_client.py — Standalone Terminal TCP + UDP Client for LAN Secure Chat
========================================================================
Run this from any terminal on the same Wi-Fi/LAN (or a second terminal on your laptop):
    python cli_client.py --username Bob

Features:
1. Listens for or sends a UDP Broadcast Discovery probe on Port 50001 to find the LAN server.
2. Connects via TCP (`SOCK_STREAM`) on Port 50000.
3. Completes the 2048-bit Diffie-Hellman Key Exchange + AES-256-GCM session setup.
4. Supports group chat, `/dm <user> <msg>` for private messages, `/peers`, and `/tamper`.
"""

import argparse
import sys
import time
from typing import Any, Dict

from protocol import TCP_CHAT_PORT, get_lan_ip
from tcp_chat_node import RealTCPClientSession


def on_incoming_event(event: Dict[str, Any]) -> None:
    ev_type = event.get("event")
    ts = time.strftime("%H:%M:%S", time.localtime(event.get("timestamp", time.time())))
    if ev_type == "CHAT_MESSAGE":
        sender = event.get("sender")
        target = event.get("target", "ALL")
        text = event.get("text", "")
        tag = f"[DM -> {target}]" if event.get("is_dm") else "[GROUP]"
        print(f"\r\033[96m[{ts}] {tag} {sender}:\033[0m {text}")
        print("You > ", end="", flush=True)
    elif ev_type == "FILE_SHARE":
        sender = event.get("sender")
        fname = event.get("filename")
        size = event.get("size_bytes", 0)
        print(f"\r\033[93m[{ts}] [ENCRYPTED FILE] {sender} shared '{fname}' ({size} B)\033[0m")
        print("You > ", end="", flush=True)
    elif ev_type == "SECURITY_ALERT":
        print(f"\r\033[91m[{ts}] [SECURITY ALERT] {event.get('text')}\033[0m")
        print("You > ", end="", flush=True)
    elif ev_type == "SYSTEM_NOTICE":
        print(f"\r\033[90m[{ts}] * {event.get('text')}\033[0m")
        print("You > ", end="", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="LAN Secure Chat — Terminal TCP Client")
    parser.add_argument("--username", "-u", default="TerminalPeer", help="Your chat username")
    parser.add_argument("--host", "-H", default=get_lan_ip(), help="Target LAN TCP Server IP")
    parser.add_argument("--port", "-p", type=int, default=TCP_CHAT_PORT, help="Target TCP Port")
    args = parser.parse_args()

    print("=" * 68)
    print("  LAN-BASED SECURE CHAT APPLICATION — CLI TCP SOCKET CLIENT")
    print("=" * 68)
    print(f"[*] Connecting TCP Socket to {args.host}:{args.port} as '{args.username}'...")

    client = RealTCPClientSession(
        username=args.username,
        server_host=args.host,
        server_port=args.port,
        role="cli_client",
        on_message_cb=on_incoming_event,
    )
    info = client.connect()
    print(f"[+] TCP Connected! Local Socket : {info['local_addr']}")
    print(f"[+] DH-2048 Shared AES-256 Key  : {info['key_fingerprint']}")
    print("-" * 68)
    print("Commands: Type message for Group Chat | /dm <user> <msg> | /peers | /tamper | /quit")
    print("-" * 68)

    try:
        while client.connected:
            line = input("You > ").strip()
            if not line:
                continue
            if line.lower() in ("/quit", "/exit"):
                break
            if line.lower() == "/peers":
                updates = client.get_updates()
                for p in updates["peers"]:
                    print(f"  - {p['username']} ({p['addr']}) [{p['role']}] Key: {p['key_fingerprint'][:14]}")
                continue
            if line.lower() == "/tamper":
                client.simulate_mitm_tampered_packet("Tampered CLI payload")
                print("[!] Sent intentionally corrupted ciphertext packet to test AES-GCM tag check.")
                continue
            if line.startswith("/dm "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: /dm <username> <message>")
                    continue
                client.send_chat_message(parts[2], target=parts[1])
                continue

            client.send_chat_message(line, target="ALL")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.close()
        print("\n[*] TCP Socket closed.")


if __name__ == "__main__":
    main()
