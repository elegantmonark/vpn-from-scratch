"""
VPN Server main module.
Handles client connections, handshake, and tunnel management.
"""

import os
import sys
import json
import socket
import threading
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Tuple

# Add parent to path for shared imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from client.crypto import CryptoManager, KeyExchange, SessionKeys, generate_keypair, load_keypair
from client.wintun import TUNInterface
from client.handshake import HandshakeServer, HANDSHAKE_PORT
from client.tunnel import TunnelServer, TunnelState


# Constants
SERVER_CONFIG_FILE = Path(__file__).parent.parent / "config" / "server.json"
SERVER_KEY_FILE = Path(__file__).parent.parent / "config" / "server.key"
VPN_SUBNET = "10.0.0"  # VPN clients get IPs in this subnet


@dataclass
class ServerConfig:
    """Server configuration."""
    name: str = "VPN Server"
    listen_port: int = 51820
    handshake_port: int = HANDSHAKE_PORT
    tun_name: str = "VPNServer"
    private_key: Optional[bytes] = None
    public_key: Optional[bytes] = None

    @classmethod
    def load(cls, path: Path = SERVER_CONFIG_FILE, key_path: Path = SERVER_KEY_FILE) -> "ServerConfig":
        """Load configuration from JSON file."""
        data = {}
        if path.exists():
            with open(path, 'r') as f:
                data = json.load(f)

        config = cls(
            name=data.get('name', 'VPN Server'),
            listen_port=data.get('listen_port', 51820),
            handshake_port=data.get('handshake_port', HANDSHAKE_PORT),
            tun_name=data.get('tun_name', 'VPNServer'),
        )

        # Backward-compatible: if legacy private_key exists in JSON, load it once.
        if data.get('private_key'):
            config.private_key = bytes.fromhex(data['private_key'])
        elif key_path.exists():
            key_text = key_path.read_text(encoding='utf-8').strip()
            if key_text:
                config.private_key = bytes.fromhex(key_text)

        if data.get('public_key'):
            config.public_key = bytes.fromhex(data['public_key'])

        # Derive public key from private key when needed.
        if config.private_key and not config.public_key:
            _, pubkey = load_keypair(config.private_key)
            config.public_key = pubkey.public_bytes_raw()

        return config

    def save(self, path: Path = SERVER_CONFIG_FILE, key_path: Path = SERVER_KEY_FILE):
        """Save configuration to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'name': self.name,
            'listen_port': self.listen_port,
            'handshake_port': self.handshake_port,
            'tun_name': self.tun_name,
        }
        if self.public_key:
            data['public_key'] = self.public_key.hex()

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        # Persist private key separately so server.json remains shareable.
        if self.private_key:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(self.private_key.hex(), encoding='utf-8')
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                # Best-effort; Windows ACLs are handled outside chmod semantics.
                pass


class VPNServer:
    """
    Complete VPN server implementation.
    Handles:
    - TCP handshake connections
    - Key exchange
    - UDP tunnel for data
    - NAT/routing for internet access
    """

    def __init__(self, config: Optional[ServerConfig] = None):
        """Initialize VPN server."""
        self.config = config or ServerConfig.load()
        self.running = False

        # Generate keys if not set
        if not self.config.private_key:
            self.config.private_key, self.config.public_key = generate_keypair()
            print(f"[Server] Generated new key pair")
            print(f"  Public key: {self.config.public_key.hex()}")

        # Handshake server
        self.handshake_server: Optional[HandshakeServer] = None
        self.tcp_socket: Optional[socket.socket] = None

        # Tunnel server
        self.tunnel_server: Optional[TunnelServer] = None

        # Connected clients
        self.clients: Dict[str, Tuple[SessionKeys, Tuple[str, int]]] = {}

        # Stats
        self.stats = {
            'connections': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': None
        }

        self._lock = threading.Lock()

    def start(self):
        """Start the VPN server."""
        print(f"[Server] Starting {self.config.name}...")
        print(f"[Server] Public key: {self.config.public_key.hex()}")

        # Start tunnel server
        self.tunnel_server = TunnelServer(self.config.tun_name)
        if not self.tunnel_server.start(self.config.listen_port):
            print("[Server] Failed to start tunnel server")
            return False

        # Start handshake listener
        self.running = True
        self.stats['start_time'] = time.time()

        # Create TCP socket for handshakes
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket.bind(("0.0.0.0", self.config.handshake_port))
        self.tcp_socket.listen(5)
        self.tcp_socket.settimeout(1.0)  # Allow checking self.running

        print(f"[Server] Listening for handshakes on port {self.config.handshake_port}")
        print(f"[Server] UDP tunnel on port {self.config.listen_port}")

        # Accept connections in a thread
        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

        # Main loop
        try:
            while self.running:
                time.sleep(1.0)
                self._print_stats()
        except KeyboardInterrupt:
            print("\n[Server] Interrupted")
        finally:
            self.stop()

    def _accept_loop(self):
        """Accept incoming handshake connections."""
        while self.running:
            try:
                conn, addr = self.tcp_socket.accept()
                print(f"[Server] Handshake connection from {addr}")

                # Handle handshake in a thread
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                handler.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[Server] Accept error: {e}")

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle a client handshake."""
        try:
            # Create handshake handler
            handshake = HandshakeServer(self.config.private_key)

            # Perform handshake
            session_keys = handshake.handle_handshake(conn, self.config.listen_port)

            if session_keys:
                # Store client info
                with self._lock:
                    self.clients[addr[0]] = (session_keys, addr)
                    self.stats['connections'] += 1

                print(f"[Server] Client {addr} authenticated")

                # Set session keys in tunnel
                self.tunnel_server.set_session_keys(session_keys)
                # UDP client address is learned from incoming tunnel packets.

                # Keep connection alive until client disconnects
                # (In a real implementation, we'd have proper session management)
                while self.running:
                    time.sleep(1.0)

        except Exception as e:
            print(f"[Server] Client {addr} error: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

            with self._lock:
                if addr[0] in self.clients:
                    del self.clients[addr[0]]

            print(f"[Server] Client {addr} disconnected")

    def _print_stats(self):
        """Print server statistics."""
        if self.tunnel_server:
            uptime = time.time() - self.stats['start_time']
            print(f"\r[Server] Uptime: {uptime:.0f}s | "
                  f"Clients: {len(self.clients)} | "
                  f"TX: {self.tunnel_server.stats.bytes_sent/1024/1024:.2f}MB | "
                  f"RX: {self.tunnel_server.stats.bytes_received/1024/1024:.2f}MB",
                  end="", flush=True)

    def stop(self):
        """Stop the VPN server."""
        print("\n[Server] Stopping...")
        self.running = False

        if self.tcp_socket:
            try:
                self.tcp_socket.close()
            except:
                pass

        if self.tunnel_server:
            self.tunnel_server.stop()

        # Save config (including generated keys)
        self.config.save()

        print("[Server] Stopped")


def setup_nat():
    """Setup NAT routing for internet access."""
    if os.name != 'nt':
        # Linux: use iptables
        import subprocess
        commands = [
            # Enable IP forwarding
            "sysctl -w net.ipv4.ip_forward=1",

            # NAT outgoing traffic
            "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",

            # Allow forwarding
            "iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT",
            "iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]

        print("[Server] Setting up NAT...")
        for cmd in commands:
            print(f"  $ {cmd}")
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"  Failed: {e}")
                print("  Note: Run as root for NAT setup")
    else:
        # Windows: requires netsh or PowerShell
        print("[Server] Windows NAT setup requires Administrator privileges")
        print("[Server] Run the following commands as Administrator:")
        print('  netsh routing ip nat install')
        print('  netsh routing ip nat add interface "VPNServer" full')
        print('  netsh routing ip nat add interface "Ethernet" private')


def main():
    """Main entry point."""
    print("=" * 60)
    print("VPN Server")
    print("=" * 60)

    # Load config
    config = ServerConfig.load()
    print(f"[Server] Configuration loaded")

    # Create server
    server = VPNServer(config)

    # Setup NAT (requires admin/root)
    # setup_nat()

    # Start server
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
