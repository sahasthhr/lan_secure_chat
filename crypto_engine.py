"""
crypto_engine.py — Cryptographic Engine for LAN Secure Chat Application
=======================================================================
Computer Networks (CN) Concepts Demonstrated:
1. Diffie-Hellman (DH) Ephemeral Key Exchange (RFC 3526 2048-bit MODP Group 14):
   Allows two peers over an insecure LAN to establish a shared secret key
   without ever transmitting the private key across the network.
2. Key Derivation Function (SHA-256 KDF):
   Converts the large DH shared integer into a 256-bit symmetric key.
3. Authenticated Encryption with Associated Data (AES-256-GCM):
   Provides both Confidentiality (AES-256 encryption) and Integrity/Authenticity
   (128-bit GCM Authentication Tag) to detect any Man-in-the-Middle (MitM)
   packet tampering in transit.
"""

import base64
import hashlib
import os
import secrets
import time
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# RFC 3526 — 2048-bit MODP Group (Group 14) Safe Prime (p) and Generator (g = 2)
DH_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_P = int(DH_PRIME_HEX, 16)
DH_G = 2


class DiffieHellmanSession:
    """
    Manages a per-socket Diffie-Hellman Key Exchange and AES-256-GCM cipher state.
    """

    def __init__(self) -> None:
        # Generate 256-bit ephemeral private key 'a'
        self.private_key: int = secrets.randbits(256)
        # Compute public key A = (g^a) mod p
        self.public_key: int = pow(DH_G, self.private_key, DH_P)
        self.peer_public_key: int | None = None
        self.aes_key: bytes | None = None
        self.aesgcm: AESGCM | None = None
        self.key_fingerprint: str = "UNINITIALIZED"
        self.established_at: float | None = None

    def get_public_key_hex(self) -> str:
        """Return our public key formatted as a hex string for network transmission."""
        return hex(self.public_key)[2:]

    def compute_shared_key(self, peer_public_key_hex: str) -> str:
        """
        Receive peer's public key B, compute Shared Secret S = (B^a) mod p,
        and derive a 256-bit AES-GCM key via SHA-256.
        Returns a human-readable key fingerprint for verification in the UI.
        """
        peer_pub = int(peer_public_key_hex, 16)
        if peer_pub <= 1 or peer_pub >= DH_P - 1:
            raise ValueError("Invalid Diffie-Hellman peer public key received.")

        self.peer_public_key = peer_pub
        # Shared secret S = (B ^ a) mod p
        shared_secret_int = pow(peer_pub, self.private_key, DH_P)
        shared_secret_bytes = shared_secret_int.to_bytes(
            (shared_secret_int.bit_length() + 7) // 8, byteorder="big"
        )

        # Derive 32-byte (256-bit) symmetric key using SHA-256 KDF
        self.aes_key = hashlib.sha256(
            b"LAN-SECURE-CHAT-AES256-GCM-KEY|" + shared_secret_bytes
        ).digest()
        self.aesgcm = AESGCM(self.aes_key)

        # Create a short visual fingerprint of the shared key (for CN Viva inspection)
        fp_digest = hashlib.sha256(b"FINGERPRINT|" + self.aes_key).hexdigest().upper()
        self.key_fingerprint = ":".join(fp_digest[i : i + 4] for i in range(0, 24, 4))
        self.established_at = time.time()
        return self.key_fingerprint

    def encrypt_payload(
        self, plaintext_str: str, aad_str: str = "LAN-CHAT-V1"
    ) -> Dict[str, Any]:
        """
        Encrypt a UTF-8 string using AES-256-GCM with a fresh 96-bit random nonce.
        Returns a dictionary ready for JSON serialization + full inspection metadata.
        """
        if self.aesgcm is None:
            raise RuntimeError("Diffie-Hellman handshake not completed yet.")

        nonce = os.urandom(12)  # 96-bit random IV/Nonce required for AES-GCM
        plaintext_bytes = plaintext_str.encode("utf-8")
        aad_bytes = aad_str.encode("utf-8")

        # AESGCM.encrypt returns ciphertext + 16-byte GCM authentication tag appended
        ct_with_tag = self.aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
        ciphertext_only = ct_with_tag[:-16]
        auth_tag = ct_with_tag[-16:]

        return {
            "alg": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ct_b64": base64.b64encode(ct_with_tag).decode("ascii"),
            "aad": aad_str,
            # Inspector metadata (hex representations for educational display)
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext_only.hex(),
            "auth_tag_hex": auth_tag.hex(),
            "key_fingerprint": self.key_fingerprint,
            "pt_len": len(plaintext_bytes),
            "ct_len": len(ct_with_tag),
        }

    def decrypt_payload(self, enc_dict: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Decrypt and authenticate an AES-256-GCM encrypted dictionary.
        Raises InvalidTag if even a single bit of ciphertext, nonce, or AAD was tampered with.
        """
        if self.aesgcm is None:
            raise RuntimeError("Diffie-Hellman handshake not completed yet.")

        nonce = base64.b64decode(enc_dict["nonce_b64"])
        ct_with_tag = base64.b64decode(enc_dict["ct_b64"])
        aad_str = enc_dict.get("aad", "LAN-CHAT-V1")
        aad_bytes = aad_str.encode("utf-8")

        ciphertext_only = ct_with_tag[:-16]
        auth_tag = ct_with_tag[-16:]

        inspector_meta = {
            "alg": enc_dict.get("alg", "AES-256-GCM"),
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext_only.hex(),
            "auth_tag_hex": auth_tag.hex(),
            "key_fingerprint": self.key_fingerprint,
            "ct_len": len(ct_with_tag),
        }

        # Verify 128-bit GCM Auth Tag & Decrypt
        plaintext_bytes = self.aesgcm.decrypt(nonce, ct_with_tag, aad_bytes)
        plaintext_str = plaintext_bytes.decode("utf-8")
        inspector_meta["pt_len"] = len(plaintext_bytes)
        return plaintext_str, inspector_meta


__all__ = ["DiffieHellmanSession", "InvalidTag", "DH_P", "DH_G"]
