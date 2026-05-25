"""
Handshake protocol for establishing VPN session keys.
Uses TCP for reliable delivery before switching to UDP tunnel.
"""

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from enum import IntEnum

from .crypto import KeyExchange, CryptoManager, SessionKeys


# Protocol constants
HANDSHAKE_PORT = 51821  # TCP port for handshake
HANDSHAKE_TIMEOUT = 10.0  # Seconds
PROTOCOL_VERSION = 1
HANDSHAKE_NONCE_SIZE = 32  # HKDF salt size for session key derivation
MAX_CLOCK_SKEW_SECONDS = 120  # Reject stale/future handshakes outside this window


class MessageType(IntEnum):
    """Handshake message types."""
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CLIENT_ACK = 3
    ERROR = 255


@dataclass
class ClientHello:
    """Initial message from client to server."""
    version: int  # Protocol version
    timestamp: int  # Unix timestamp (8 bytes)
    public_key: bytes  # Client's X25519 public key (32 bytes)

    def serialize(self) -> bytes:
        """Pack into bytes."""
        return struct.pack(
            "!BQ32s",
            self.version,
            self.timestamp,
            self.public_key
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientHello":
        """Unpack from bytes."""
        version, timestamp, public_key = struct.unpack("!BQ32s", data)
        return cls(version=version, timestamp=timestamp, public_key=public_key)


@dataclass
class ServerHello:
    """Server response with its public key and key-derivation nonce."""
    public_key: bytes  # Server's X25519 public key (32 bytes)
    nonce: bytes  # Random nonce/salt for key derivation (32 bytes)

    def serialize(self) -> bytes:
        """Pack into bytes."""
        return struct.pack("!32s", self.public_key) + self.nonce

    @classmethod
    def deserialize(cls, data: bytes) -> "ServerHello":
        """Unpack from bytes."""
        public_key = data[:32]
        nonce = data[32:]
        return cls(public_key=public_key, nonce=nonce)


@dataclass
class ClientAck:
    """Client acknowledgment to confirm key agreement."""
    encrypted_confirm: bytes  # Encrypted confirmation message

    def serialize(self) -> bytes:
        return self.encrypted_confirm

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientAck":
        return cls(encrypted_confirm=data)


@dataclass
class HandshakeResult:
    """Result of a successful handshake."""
    session_keys: SessionKeys
    server_address: Tuple[str, int]
    udp_port: int  # UDP port to use for tunnel


class HandshakeError(Exception):
    """Handshake failed."""
    pass


class HandshakeClient:
    """
    Client-side handshake implementation.
    Establishes session keys with server before opening UDP tunnel.
    """

    def __init__(self, server_pubkey: Optional[bytes] = None, allow_insecure: bool = False):
        """
        Initialize handshake client.

        Args:
            server_pubkey: Optional known server public key for authentication.
            allow_insecure: If True, allow handshake without pinned server key.
                          Use only for local testing.
        """
        self.key_exchange = KeyExchange()
        self.server_pubkey = server_pubkey
        self.allow_insecure = allow_insecure
        self.session_keys: Optional[SessionKeys] = None

    def perform_handshake(self, host: str, port: int = HANDSHAKE_PORT,
                          timeout: float = HANDSHAKE_TIMEOUT) -> HandshakeResult:
        """
        Perform the handshake with the VPN server.

        Args:
            host: Server hostname or IP
            port: Server handshake port (TCP)
            timeout: Connection timeout in seconds

        Returns:
            HandshakeResult with session keys and server info

        Raises:
            HandshakeError: If handshake fails
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            print(f"[Handshake] Connecting to {host}:{port}...")
            sock.connect((host, port))

            # Step 1: Send ClientHello
            client_hello = ClientHello(
                version=PROTOCOL_VERSION,
                timestamp=int(time.time()),
                public_key=self.key_exchange.get_public_key_bytes()
            )
            self._send_message(sock, MessageType.CLIENT_HELLO, client_hello.serialize())
            print(f"[Handshake] Sent ClientHello")

            # Step 2: Receive ServerHello
            msg_type, server_data = self._recv_message(sock)
            if msg_type != MessageType.SERVER_HELLO:
                raise HandshakeError(f"Expected ServerHello, got {msg_type}")

            server_hello = ServerHello.deserialize(server_data)
            print(f"[Handshake] Received ServerHello")

            # Verify server identity with key pinning (secure default).
            if self.server_pubkey:
                if server_hello.public_key != self.server_pubkey:
                    raise HandshakeError("Server public key mismatch - possible MITM attack!")
            elif not self.allow_insecure:
                raise HandshakeError(
                    "Server public key is not pinned. Configure a trusted pubkey first, "
                    "or explicitly allow insecure mode for local testing."
                )

            # Step 3: Derive session keys
            if len(server_hello.nonce) != HANDSHAKE_NONCE_SIZE:
                raise HandshakeError(f"Invalid handshake nonce size: {len(server_hello.nonce)}")
            nonce = server_hello.nonce

            # Derive session keys
            self.session_keys = self.key_exchange.derive_session_keys(
                server_hello.public_key,
                nonce
            )
            print(f"[Handshake] Derived session keys")

            # Step 4: Send ClientAck (encrypted confirmation)
            # Encrypt a known message with the session key to prove we have the key
            confirm_msg = b"HANDSHAKE_CONFIRM"
            crypto = CryptoManager(self.session_keys.encrypt_key)
            encrypted_confirm = crypto.encrypt(confirm_msg)

            client_ack = ClientAck(encrypted_confirm=encrypted_confirm)
            self._send_message(sock, MessageType.CLIENT_ACK, client_ack.serialize())
            print(f"[Handshake] Sent ClientAck")

            # Step 5: Receive confirmation with UDP port
            msg_type, final_data = self._recv_message(sock)
            if msg_type != MessageType.CLIENT_ACK:
                raise HandshakeError(f"Expected final ack, got {msg_type}")

            # Parse UDP port from response
            udp_port = struct.unpack("!H", final_data[:2])[0]
            print(f"[Handshake] UDP tunnel will use port {udp_port}")

            sock.close()

            return HandshakeResult(
                session_keys=self.session_keys,
                server_address=(host, udp_port),
                udp_port=udp_port
            )

        except socket.timeout:
            raise HandshakeError("Handshake timed out")
        except socket.error as e:
            raise HandshakeError(f"Socket error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass

    def _send_message(self, sock: socket.socket, msg_type: MessageType, data: bytes):
        """Send a typed message with length prefix."""
        # Format: [type (1 byte)][length (4 bytes)][data]
        header = struct.pack("!BI", msg_type, len(data))
        sock.sendall(header + data)

    def _recv_message(self, sock: socket.socket, max_size: int = 65536) -> Tuple[MessageType, bytes]:
        """Receive a typed message with length prefix."""
        # Read header
        header = self._recv_exact(sock, 5)
        msg_type, length = struct.unpack("!BI", header)

        if length > max_size:
            raise HandshakeError(f"Message too large: {length}")

        # Read data
        data = self._recv_exact(sock, length)
        return MessageType(msg_type), data

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise HandshakeError("Connection closed unexpectedly")
            data += chunk
        return data


class HandshakeServer:
    """
    Server-side handshake implementation.
    Handles incoming client connections and establishes session keys.
    """

    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialize handshake server.

        Args:
            private_key: Optional static private key. If None, generates ephemeral key.
        """
        if private_key:
            from .crypto import load_keypair
            self.private_key, self.public_key = load_keypair(private_key)
        else:
            self.key_exchange = KeyExchange()
            self.private_key = self.key_exchange.private_key
            self.public_key = self.key_exchange.public_key

    def handle_handshake(self, client_sock: socket.socket, udp_port: int) -> Optional[SessionKeys]:
        """
        Handle a client handshake.

        Args:
            client_sock: Connected client socket
            udp_port: UDP port to tell client to use

        Returns:
            SessionKeys if successful, None if failed
        """
        try:
            # Step 1: Receive ClientHello
            msg_type, data = self._recv_message(client_sock)
            if msg_type != MessageType.CLIENT_HELLO:
                return None

            client_hello = ClientHello.deserialize(data)
            print(f"[Server] Received ClientHello (version {client_hello.version})")

            # Verify version
            if client_hello.version != PROTOCOL_VERSION:
                self._send_error(client_sock, f"Unsupported version {client_hello.version}")
                return None

            # Basic replay/staleness protection.
            now = int(time.time())
            if abs(now - client_hello.timestamp) > MAX_CLOCK_SKEW_SECONDS:
                self._send_error(client_sock, "ClientHello timestamp outside allowed window")
                return None

            # Step 2: Derive shared secret and session keys
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
            client_pubkey = X25519PublicKey.from_public_bytes(client_hello.public_key)
            shared_secret = self.private_key.exchange(client_pubkey)

            # Use a random nonce/salt per handshake for HKDF key separation.
            nonce = os.urandom(HANDSHAKE_NONCE_SIZE)

            # Derive session keys.
            temp_key_exchange = KeyExchange()
            temp_key_exchange.private_key = self.private_key
            temp_key_exchange.public_key = self.public_key

            session_keys = temp_key_exchange.derive_session_keys(client_hello.public_key, nonce)

            # Step 3: Send ServerHello
            server_hello = ServerHello(
                public_key=self.public_key.public_bytes_raw(),
                nonce=nonce
            )
            self._send_message(client_sock, MessageType.SERVER_HELLO, server_hello.serialize())
            print(f"[Server] Sent ServerHello")

            # Step 4: Receive ClientAck
            msg_type, data = self._recv_message(client_sock)
            if msg_type != MessageType.CLIENT_ACK:
                return None

            client_ack = ClientAck.deserialize(data)

            # Verify the encrypted confirmation
            crypto = CryptoManager(session_keys.decrypt_key)
            try:
                confirm_msg = crypto.decrypt(client_ack.encrypted_confirm)
                if confirm_msg != b"HANDSHAKE_CONFIRM":
                    print("[Server] Invalid confirmation message")
                    return None
            except ValueError as e:
                print(f"[Server] Failed to decrypt confirmation: {e}")
                return None

            print(f"[Server] Handshake successful")

            # Step 5: Send UDP port
            self._send_message(client_sock, MessageType.CLIENT_ACK, struct.pack("!H", udp_port))

            return session_keys

        except Exception as e:
            print(f"[Server] Handshake error: {e}")
            return None

    def _send_message(self, sock: socket.socket, msg_type: MessageType, data: bytes):
        """Send a typed message with length prefix."""
        header = struct.pack("!BI", msg_type, len(data))
        sock.sendall(header + data)

    def _recv_message(self, sock: socket.socket, max_size: int = 65536) -> Tuple[MessageType, bytes]:
        """Receive a typed message with length prefix."""
        header = self._recv_exact(sock, 5)
        msg_type, length = struct.unpack("!BI", header)

        if length > max_size:
            raise HandshakeError(f"Message too large: {length}")

        data = self._recv_exact(sock, length)
        return MessageType(msg_type), data

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise HandshakeError("Connection closed unexpectedly")
            data += chunk
        return data

    def _send_error(self, sock: socket.socket, message: str):
        """Send an error message."""
        self._send_message(sock, MessageType.ERROR, message.encode())


if __name__ == "__main__":
    # Test handshake
    print("Testing handshake protocol...")

    import threading
    import time

    # Create server
    server = HandshakeServer()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", HANDSHAKE_PORT))
    server_sock.listen(1)
    server_sock.settimeout(5.0)

    def run_server():
        conn, addr = server_sock.accept()
        keys = server.handle_handshake(conn, 51820)
        if keys:
            print(f"[Server] Session established!")
            print(f"  Encrypt key: {keys.encrypt_key.hex()[:32]}...")
        conn.close()
        server_sock.close()

    # Start server thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Run client
    time.sleep(0.1)
    client = HandshakeClient()
    result = client.perform_handshake("127.0.0.1", timeout=5.0)

    print(f"\n[Client] Session established!")
    print(f"  UDP port: {result.udp_port}")
    print(f"  Encrypt key: {result.session_keys.encrypt_key.hex()[:32]}...")

    server_thread.join(timeout=2.0)
    print("\nHandshake test complete!")
