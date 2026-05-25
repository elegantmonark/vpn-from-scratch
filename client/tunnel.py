"""
UDP tunnel implementation for VPN data transport.
Handles packet forwarding between TUN interface and UDP socket.
"""

import os
import socket
import threading
import time
import select
from dataclasses import dataclass, field
from typing import Optional, Callable, Tuple
from enum import IntEnum
from collections import deque
import struct

from .wintun import TUNInterface
from .crypto import CryptoManager, SessionKeys


# Constants
UDP_PORT = 51820
MTU = 1500
BUFFER_SIZE = 65535
KEEPALIVE_INTERVAL = 15.0  # seconds


class TunnelState(IntEnum):
    """Tunnel connection state."""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    DISCONNECTING = 3
    ERROR = 4


@dataclass
class TunnelStats:
    """Statistics for tunnel traffic."""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def duration_seconds(self) -> float:
        """Connection duration in seconds."""
        return time.time() - self.start_time

    @property
    def send_rate_mbps(self) -> float:
        """Send rate in Mbps."""
        if self.duration_seconds == 0:
            return 0
        return (self.bytes_sent * 8) / (self.duration_seconds * 1_000_000)

    @property
    def recv_rate_mbps(self) -> float:
        """Receive rate in Mbps."""
        if self.duration_seconds == 0:
            return 0
        return (self.bytes_received * 8) / (self.duration_seconds * 1_000_000)


class TunnelClient:
    """
    VPN tunnel client.
    Encrypts packets from TUN and sends over UDP to server.
    Receives encrypted packets from UDP, decrypts, and writes to TUN.
    """

    def __init__(self, tun_name: str = "MyVPN"):
        """
        Initialize tunnel client.

        Args:
            tun_name: Name for the TUN interface
        """
        self.tun_name = tun_name
        self.tun: Optional[TUNInterface] = None
        self.udp_sock: Optional[socket.socket] = None
        self.state = TunnelState.DISCONNECTED
        self.stats = TunnelStats()

        self._session_keys: Optional[SessionKeys] = None
        self._encryptor: Optional[CryptoManager] = None
        self._decryptor: Optional[CryptoManager] = None
        self._server_addr: Optional[Tuple[str, int]] = None

        self._running = False
        self._threads: list = []
        self._lock = threading.Lock()
        self._on_state_change: Optional[Callable[[TunnelState], None]] = None
        self._on_stats_update: Optional[Callable[[TunnelStats], None]] = None

    def set_session_keys(self, keys: SessionKeys):
        """Set session keys after handshake."""
        self._session_keys = keys
        self._encryptor = CryptoManager(keys.encrypt_key)
        self._decryptor = CryptoManager(keys.decrypt_key)

    def connect(self, server_host: str, server_port: int = UDP_PORT,
                session_keys: Optional[SessionKeys] = None) -> bool:
        """
        Connect to VPN server.

        Args:
            server_host: Server hostname or IP
            server_port: Server UDP port
            session_keys: Pre-established session keys (from handshake)

        Returns:
            True if connected successfully
        """
        with self._lock:
            if self.state == TunnelState.CONNECTED:
                return True

            self._set_state(TunnelState.CONNECTING)

            try:
                # Set up session keys
                if session_keys:
                    self.set_session_keys(session_keys)

                if not self._encryptor or not self._decryptor:
                    raise RuntimeError("No session keys set. Run handshake first.")

                # Create TUN interface
                self.tun = TUNInterface(self.tun_name)
                self.tun.create()
                self.tun.start()
                self.tun.configure("10.8.0.2")
                print(f"[Tunnel] Created TUN interface: {self.tun_name}")

                # Create UDP socket
                self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_sock.bind(("0.0.0.0", 0))  # Bind to any available port

                self._server_addr = (server_host, server_port)

                # Start worker threads
                self._running = True
                self._start_threads()

                self._set_state(TunnelState.CONNECTED)
                print(f"[Tunnel] Connected to {server_host}:{server_port}")
                return True

            except Exception as e:
                print(f"[Tunnel] Connection failed: {e}")
                self._set_state(TunnelState.ERROR)
                self._cleanup()
                return False

    def disconnect(self):
        """Disconnect from VPN server."""
        with self._lock:
            if self.state == TunnelState.DISCONNECTED:
                return

            self._set_state(TunnelState.DISCONNECTING)
            self._running = False

            # Wait for threads to stop
            for thread in self._threads:
                if thread.is_alive():
                    thread.join(timeout=2.0)

            self._cleanup()
            self._set_state(TunnelState.DISCONNECTED)
            print("[Tunnel] Disconnected")

    def _set_state(self, state: TunnelState):
        """Update state and notify callback."""
        self.state = state
        if self._on_state_change:
            self._on_state_change(state)

    def _start_threads(self):
        """Start worker threads for packet processing."""
        # TUN -> UDP thread
        tun_thread = threading.Thread(target=self._tun_to_udp, daemon=True)
        tun_thread.start()
        self._threads.append(tun_thread)

        # UDP -> TUN thread
        udp_thread = threading.Thread(target=self._udp_to_tun, daemon=True)
        udp_thread.start()
        self._threads.append(udp_thread)

        # Keepalive thread
        keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        keepalive_thread.start()
        self._threads.append(keepalive_thread)

    def _tun_to_udp(self):
        """Read from TUN, encrypt, and send to UDP."""
        print("[Tunnel] TUN→UDP thread started")

        while self._running:
            try:
                # Read packet from TUN
                packet = self.tun.read(timeout_ms=1000)

                if packet and self._encryptor and self._server_addr:
                    # Encrypt packet
                    encrypted = self._encryptor.encrypt(packet)

                    # Send to server
                    self.udp_sock.sendto(encrypted, self._server_addr)

                    # Update stats
                    self.stats.bytes_sent += len(encrypted)
                    self.stats.packets_sent += 1
                    self._notify_stats()

            except Exception as e:
                if self._running:
                    print(f"[Tunnel] TUN→UDP error: {e}")

    def _udp_to_tun(self):
        """Receive from UDP, decrypt, and write to TUN."""
        print("[Tunnel] UDP→TUN thread started")

        while self._running:
            try:
                # Use select for timeout
                ready = select.select([self.udp_sock], [], [], 1.0)

                if ready[0]:
                    data, addr = self.udp_sock.recvfrom(BUFFER_SIZE)

                    # Verify it's from our server
                    if addr != self._server_addr:
                        continue

                    if self._decryptor:
                        # Decrypt packet
                        try:
                            decrypted = self._decryptor.decrypt(data)

                            # Write to TUN
                            if not decrypted:
                                continue
                            self.tun.write(decrypted)

                            # Update stats
                            self.stats.bytes_received += len(data)
                            self.stats.packets_received += 1
                            self._notify_stats()

                        except ValueError as e:
                            print(f"[Tunnel] Decryption failed: {e}")

            except Exception as e:
                if self._running:
                    print(f"[Tunnel] UDP→TUN error: {e}")

    def _keepalive_loop(self):
        """Send periodic keepalive packets."""
        print("[Tunnel] Keepalive thread started")

        while self._running:
            time.sleep(KEEPALIVE_INTERVAL)

            if self._running and self._encryptor and self._server_addr:
                # Send empty encrypted packet as keepalive
                try:
                    keepalive = self._encryptor.encrypt(b"")
                    self.udp_sock.sendto(keepalive, self._server_addr)
                except Exception as e:
                    print(f"[Tunnel] Keepalive failed: {e}")

    def _cleanup(self):
        """Clean up resources."""
        if self.tun:
            try:
                self.tun.close()
            except:
                pass
            self.tun = None

        if self.udp_sock:
            try:
                self.udp_sock.close()
            except:
                pass
            self.udp_sock = None

    def _notify_stats(self):
        """Notify stats callback."""
        if self._on_stats_update:
            self._on_stats_update(self.stats)

    def set_state_callback(self, callback: Callable[[TunnelState], None]):
        """Set callback for state changes."""
        self._on_state_change = callback

    def set_stats_callback(self, callback: Callable[[TunnelStats], None]):
        """Set callback for stats updates."""
        self._on_stats_update = callback

    def get_state_name(self) -> str:
        """Get human-readable state name."""
        return {
            TunnelState.DISCONNECTED: "Disconnected",
            TunnelState.CONNECTING: "Connecting...",
            TunnelState.CONNECTED: "Connected",
            TunnelState.DISCONNECTING: "Disconnecting...",
            TunnelState.ERROR: "Error"
        }.get(self.state, "Unknown")


class TunnelServer:
    """
    VPN tunnel server.
    Receives encrypted packets from UDP, decrypts, and writes to TUN.
    Encrypts packets from TUN and sends over UDP to client.
    """

    def __init__(self, tun_name: str = "VPNServer"):
        """Initialize tunnel server."""
        self.tun_name = tun_name
        self.tun: Optional[TUNInterface] = None
        self.udp_sock: Optional[socket.socket] = None
        self.state = TunnelState.DISCONNECTED
        self.stats = TunnelStats()

        self._session_keys: Optional[SessionKeys] = None
        self._encryptor: Optional[CryptoManager] = None
        self._decryptor: Optional[CryptoManager] = None
        self._client_addr: Optional[Tuple[str, int]] = None

        self._running = False
        self._threads: list = []
        self._lock = threading.Lock()

    def set_session_keys(self, keys: SessionKeys):
        """Set session keys after handshake."""
        # Keys from HandshakeServer are already in server perspective.
        self._session_keys = keys
        self._encryptor = CryptoManager(keys.encrypt_key)
        self._decryptor = CryptoManager(keys.decrypt_key)

    def start(self, port: int = UDP_PORT) -> bool:
        """
        Start VPN server.

        Args:
            port: UDP port to listen on

        Returns:
            True if started successfully
        """
        with self._lock:
            if self.state == TunnelState.CONNECTED:
                return True

            try:
                # Create TUN interface
                self.tun = TUNInterface(self.tun_name)
                self.tun.create()
                self.tun.start()
                self.tun.configure("10.8.0.1/24")
                print(f"[Server] Created TUN interface: {self.tun_name}")

                # Create UDP socket
                self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_sock.bind(("0.0.0.0", port))

                self._running = True
                self.state = TunnelState.CONNECTED

                # Start worker threads
                self._start_threads()

                print(f"[Server] Listening on UDP port {port}")
                return True

            except Exception as e:
                print(f"[Server] Start failed: {e}")
                self._cleanup()
                self.state = TunnelState.ERROR
                return False

    def stop(self):
        """Stop VPN server."""
        with self._lock:
            self._running = False
            self.state = TunnelState.DISCONNECTING

            for thread in self._threads:
                if thread.is_alive():
                    thread.join(timeout=2.0)

            self._cleanup()
            self.state = TunnelState.DISCONNECTED
            print("[Server] Stopped")

    def set_client_address(self, addr: Tuple[str, int]):
        """Set client address after handshake."""
        self._client_addr = addr

    def _start_threads(self):
        """Start worker threads."""
        # UDP receive thread
        recv_thread = threading.Thread(target=self._udp_receive_loop, daemon=True)
        recv_thread.start()
        self._threads.append(recv_thread)

        # TUN read thread
        tun_thread = threading.Thread(target=self._tun_read_loop, daemon=True)
        tun_thread.start()
        self._threads.append(tun_thread)

    def _udp_receive_loop(self):
        """Receive encrypted packets from clients."""
        print("[Server] UDP receive thread started")

        while self._running:
            try:
                ready = select.select([self.udp_sock], [], [], 1.0)

                if ready[0]:
                    data, addr = self.udp_sock.recvfrom(BUFFER_SIZE)

                    # Store client address
                    self._client_addr = addr

                    if self._decryptor:
                        try:
                            decrypted = self._decryptor.decrypt(data)
                            if not decrypted:
                                continue
                            self.tun.write(decrypted)
                            self.stats.bytes_received += len(data)
                        except ValueError as e:
                            print(f"[Server] Decryption failed: {e}")

            except Exception as e:
                if self._running:
                    print(f"[Server] UDP receive error: {e}")

    def _tun_read_loop(self):
        """Read from TUN and send to client."""
        print("[Server] TUN read thread started")

        while self._running:
            try:
                packet = self.tun.read(timeout_ms=1000)

                if packet and self._encryptor and self._client_addr:
                    encrypted = self._encryptor.encrypt(packet)
                    self.udp_sock.sendto(encrypted, self._client_addr)
                    self.stats.bytes_sent += len(encrypted)

            except Exception as e:
                if self._running:
                    print(f"[Server] TUN read error: {e}")

    def _cleanup(self):
        """Clean up resources."""
        if self.tun:
            try:
                self.tun.close()
            except:
                pass
            self.tun = None

        if self.udp_sock:
            try:
                self.udp_sock.close()
            except:
                pass
            self.udp_sock = None


# Test function
def test_tunnel():
    """Test tunnel without encryption (for debugging)."""
    print("Testing tunnel (no encryption)...")

    # This is a minimal test - real usage requires Wintun driver
    from .crypto import SessionKeys
    import os

    # Generate fake session keys
    key = os.urandom(32)
    fake_keys = SessionKeys(encrypt_key=key, decrypt_key=key)

    print("Tunnel test requires Wintun driver and admin privileges.")
    print("Run with: python -m client.tunnel")


if __name__ == "__main__":
    test_tunnel()
