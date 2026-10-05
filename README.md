# NetShield LAN — Secure TCP/UDP Chat & Packet Inspector (CN Project)

A complete **Computer Networks (CN)** project implementing a **LAN-Based Secure Chat & File-Sharing Application** using Python raw sockets (`TCP SOCK_STREAM` + `UDP SOCK_DGRAM`), **2048-bit Diffie-Hellman Ephemeral Key Exchange**, and **AES-256-GCM Authenticated Encryption**.

## Quick Start

### 1. Run the Main Server + Web Dashboard
```powershell
python app.py
```
Then open **[http://localhost:8080](http://localhost:8080)** in your browser (or `http://<YOUR-LAN-IP>:8080` from any other laptop/phone on the same Wi-Fi/Hotspot).

### 2. Optional: Connect from a Terminal CLI Client
Open a second terminal (on the same PC or another PC on the Wi-Fi) and run:
```powershell
python cli_client.py --username Bob
```

## Project Files
- `crypto_engine.py` — 2048-bit Diffie-Hellman Key Exchange (`RFC 3526 MODP Group 14`) + `AES-256-GCM` encryption & 128-bit authentication tag verification.
- `protocol.py` — Custom Application-Layer framing using a **4-byte Big-Endian Unsigned Integer (`!I`)** length header to prevent TCP byte-stream sticking.
- `udp_discovery.py` — Connectionless **UDP Broadcast (`255.255.255.255:50001`, `SO_BROADCAST`)** peer discovery service.
- `tcp_chat_node.py` — Multi-threaded **TCP Chat Server (`0.0.0.0:50000`)**, real OS TCP client sessions, and Wireshark-style live packet capture buffer.
- `cli_client.py` — Standalone command-line TCP socket client.
- `app.py` & `static/` — Modern Web Dashboard UI with a live **Packet & Crypto Inspector** and **Man-in-the-Middle (MitM) Tamper Simulator**.
