"""
Cryptographic utilities for VPN encryption.
Uses AES-256-GCM for authenticated encryption and X25519 for key exchange.
"""

import os
import hashlib
from typing import Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Constants
NONCE_SIZE = 12  # 96-bit nonce for AES-GCM
KEY_SIZE = 32    # 256-bit key
PUBLIC_KEY_SIZE = 32  # X25519 public key size
PRIVATE_KEY_SIZE = 32  # X25519 private key size


@dataclass
class SessionKeys:
    """Session keys derived from key exchange."""
    encrypt_key: bytes  # Key for client→server encryption
    decrypt_key: bytes  # Key for server→client decryption


class CryptoManager:
    """
    Manages encryption/decryption for VPN packets.
    Uses AES-256-GCM with random nonces for each packet.
    """

    def __init__(self, key: bytes):
        """
        Initialize crypto manager with a session key.

        Args:
            key: 32-byte session key for AES-256-GCM
        """
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

        self.key = key
        self.aesgcm = AESGCM(key)
        self._sequence_number = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a packet with AES-256-GCM.

        Format: [nonce (12 bytes)][ciphertext with tag]

        Args:
            plaintext: Raw packet data

        Returns:
            Encrypted packet with nonce prepended
        """
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt a packet with AES-256-GCM.

        Args:
            data: Encrypted packet [nonce][ciphertext]

        Returns:
            Decrypted packet data

        Raises:
            ValueError: If decryption fails (wrong key or corrupted data)
        """
        if len(data) < NONCE_SIZE + 16:  # Minimum: nonce + auth tag
            raise ValueError("Packet too small")

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]

        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


class KeyExchange:
    """
    X25519 key exchange for establishing session keys.
    Provides forward secrecy with ephemeral keys.
    """

    def __init__(self):
        """Generate new ephemeral key pair."""
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self) -> bytes:
        """Get public key as 32-byte raw bytes."""
        return self.public_key.public_bytes_raw()

    def derive_session_key(self, peer_public_key: bytes, nonce: Optional[bytes] = None) -> bytes:
        """
        Derive a session key from the shared secret.

        Args:
            peer_public_key: Peer's 32-byte X25519 public key
            nonce: Optional nonce for key derivation (generated if not provided)

        Returns:
            32-byte session key
        """
        if len(peer_public_key) != PUBLIC_KEY_SIZE:
            raise ValueError(f"Peer public key must be {PUBLIC_KEY_SIZE} bytes")

        # Convert peer public key
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key)

        # Compute shared secret
        shared_secret = self.private_key.exchange(peer_pub)

        # Derive session key using HKDF
        if nonce is None:
            nonce = os.urandom(32)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=nonce,
            info=b"vpn-session-key",
            backend=default_backend()
        )

        session_key = hkdf.derive(shared_secret)
        return session_key

    def derive_session_keys(self, peer_public_key: bytes, nonce: bytes) -> SessionKeys:
        """
        Derive bidirectional session keys.

        One key for encryption, one for decryption (prevents key reuse).
        Keys are directional based on public key ordering.

        Args:
            peer_public_key: Peer's 32-byte X25519 public key
            nonce: Shared nonce from handshake

        Returns:
            SessionKeys with encrypt_key and decrypt_key
        """
        # Compute shared secret
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = self.private_key.exchange(peer_pub)

        # Get our public key bytes for comparison
        my_pub = self.public_key.public_bytes_raw()

        # Determine if we're the "initiator" (lexicographically smaller public key)
        # This ensures both parties derive opposite keys
        is_initiator = my_pub < peer_public_key

        # Derive two keys using HKDF
        # Initiator uses key1 for encrypt, key2 for decrypt
        # Responder uses key2 for encrypt, key1 for decrypt
        hkdf_key1 = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=nonce,
            info=b"vpn-key-1",
            backend=default_backend()
        )

        hkdf_key2 = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=nonce,
            info=b"vpn-key-2",
            backend=default_backend()
        )

        key1 = hkdf_key1.derive(shared_secret)
        key2 = hkdf_key2.derive(shared_secret)

        if is_initiator:
            return SessionKeys(encrypt_key=key1, decrypt_key=key2)
        else:
            return SessionKeys(encrypt_key=key2, decrypt_key=key1)


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a static X25519 key pair for long-term identity.

    Returns:
        Tuple of (private_key, public_key), both 32 bytes
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    return private_bytes, public_bytes


def load_keypair(private_bytes: bytes) -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Load a key pair from private key bytes.

    Args:
        private_bytes: 32-byte private key

    Returns:
        Tuple of (private_key, public_key) objects
    """
    private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()
    return private_key, public_key


# Test functions
def test_encryption():
    """Test AES-GCM encryption/decryption."""
    print("Testing AES-GCM encryption...")

    # Generate random key
    key = os.urandom(KEY_SIZE)
    crypto = CryptoManager(key)

    # Test data
    test_packet = b"Hello, VPN World! This is a test packet."

    # Encrypt
    encrypted = crypto.encrypt(test_packet)
    print(f"Original: {len(test_packet)} bytes")
    print(f"Encrypted: {len(encrypted)} bytes (includes nonce + auth tag)")

    # Decrypt
    decrypted = crypto.decrypt(encrypted)
    assert decrypted == test_packet, "Decryption mismatch!"
    print("[OK] Encryption/decryption successful")

    # Test with wrong key
    wrong_key = os.urandom(KEY_SIZE)
    wrong_crypto = CryptoManager(wrong_key)
    try:
        wrong_crypto.decrypt(encrypted)
        print("[FAIL] Should have failed with wrong key!")
    except ValueError:
        print("[OK] Correctly rejected wrong key")


def test_key_exchange():
    """Test X25519 key exchange."""
    print("\nTesting X25519 key exchange...")

    # Create two parties
    alice = KeyExchange()
    bob = KeyExchange()

    print(f"Alice public key: {alice.get_public_key_bytes().hex()[:32]}...")
    print(f"Bob public key:   {bob.get_public_key_bytes().hex()[:32]}...")

    # Exchange and derive keys
    alice_keys = alice.derive_session_keys(bob.get_public_key_bytes(), b"shared-nonce")
    bob_keys = bob.derive_session_keys(alice.get_public_key_bytes(), b"shared-nonce")

    # Keys should match (but swapped for encryption/decryption)
    assert alice_keys.encrypt_key == bob_keys.decrypt_key, "Encrypt key mismatch!"
    assert alice_keys.decrypt_key == bob_keys.encrypt_key, "Decrypt key mismatch!"

    print("[OK] Key exchange successful")
    print(f"  Alice encrypt key: {alice_keys.encrypt_key.hex()[:32]}...")
    print(f"  Bob decrypt key:   {bob_keys.decrypt_key.hex()[:32]}...")

    # Test encryption across parties
    alice_crypto = CryptoManager(alice_keys.encrypt_key)
    bob_crypto = CryptoManager(bob_keys.decrypt_key)

    message = b"Secret message from Alice to Bob"
    encrypted = alice_crypto.encrypt(message)
    decrypted = bob_crypto.decrypt(encrypted)

    assert decrypted == message, "Cross-party decryption failed!"
    print("[OK] Cross-party encryption successful")


if __name__ == "__main__":
    test_encryption()
    test_key_exchange()
    print("\nAll crypto tests passed!")