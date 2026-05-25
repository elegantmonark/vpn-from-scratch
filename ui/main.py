"""
VPN Client UI - Tkinter Implementation.
Modern-looking interface with server selection and live stats.
"""

import os
import sys
import json
import ipaddress
import threading
import time
import subprocess
import platform
from pathlib import Path
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field

# Tkinter imports
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from client.tunnel import TunnelClient, TunnelState, TunnelStats
from client.handshake import HandshakeClient, HandshakeResult
from client.crypto import SessionKeys


# Constants
CONFIG_FILE = Path(__file__).parent.parent / "config" / "servers.json"
WINDOW_WIDTH = 400
WINDOW_HEIGHT = 590


# Country flag emojis (using Unicode)
FLAGS = {
    "US": "🇺🇸",
    "EU": "🇪🇺",
    "DE": "🇩🇪",
    "FR": "🇫🇷",
    "GB": "🇬🇧",
    "SG": "🇸🇬",
    "JP": "🇯🇵",
    "AU": "🇦🇺",
    "CA": "🇨🇦",
    "NL": "🇳🇱",
    "Local": "💻",
    "default": "🌍"
}


@dataclass
class ServerInfo:
    """Information about a VPN server."""
    name: str
    host: str
    port: int
    handshake_port: int = 51821
    pubkey: Optional[bytes] = None
    region: str = "default"
    allow_insecure: bool = False
    latency: Optional[float] = None  # milliseconds

    @classmethod
    def from_dict(cls, data: dict) -> "ServerInfo":
        """Create from JSON dict."""
        port = int(data.get('port', 51820))
        handshake_port_raw = data.get('handshake_port')
        if handshake_port_raw is None:
            handshake_port = port + 1
        else:
            handshake_port = int(handshake_port_raw)

        pubkey = None
        if 'pubkey' in data and data['pubkey']:
            pubkey = bytes.fromhex(data['pubkey']) if isinstance(data['pubkey'], str) else data['pubkey']

        allow_insecure = data.get('allow_insecure', False)
        if isinstance(allow_insecure, str):
            allow_insecure = allow_insecure.strip().lower() in ("1", "true", "yes")

        return cls(
            name=data.get('name', 'Unknown'),
            host=data.get('host', '127.0.0.1'),
            port=port,
            handshake_port=handshake_port,
            pubkey=pubkey,
            region=data.get('region', 'default'),
            allow_insecure=bool(allow_insecure)
        )

    def to_dict(self) -> dict:
        """Convert to JSON dict."""
        return {
            'name': self.name,
            'host': self.host,
            'port': self.port,
            'handshake_port': self.handshake_port,
            'pubkey': self.pubkey.hex() if self.pubkey else None,
            'region': self.region,
            'allow_insecure': self.allow_insecure
        }


def get_flag(region: str) -> str:
    """Get flag emoji for region."""
    return FLAGS.get(region, FLAGS["default"])


def ping_server(host: str, port: int, timeout: float = 2.0) -> Optional[float]:
    """
    Ping a server and return latency in milliseconds.
    Uses a simple socket connection test.
    """
    try:
        import socket
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            return (time.time() - start) * 1000  # Convert to ms

        # Try ICMP ping as fallback
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

        try:
            start = time.time()
            subprocess.run(cmd, capture_output=True, timeout=timeout)
            return (time.time() - start) * 1000
        except:
            return None

    except Exception:
        return None


class WindowsRouteManager:
    """Temporarily route IPv4 internet traffic through the VPN gateway."""

    VPN_GATEWAY = "10.8.0.1"

    def __init__(self):
        self.enabled = False
        self.server_host: Optional[str] = None

    def enable_full_vpn(self, server_host: str):
        """Add temporary split-default routes through the VPN."""
        if platform.system() != "Windows":
            raise RuntimeError("Full VPN route mode is currently implemented for Windows only.")

        self.server_host = server_host
        self.disable_full_vpn()

        # Keep the control connection outside the tunnel for public remote servers.
        gateway = self._detect_default_gateway()
        if gateway and not self._is_private_or_local(server_host):
            self._run_route(["add", server_host, "mask", "255.255.255.255", gateway])

        self._run_route(["add", "0.0.0.0", "mask", "128.0.0.0", self.VPN_GATEWAY])
        self._run_route(["add", "128.0.0.0", "mask", "128.0.0.0", self.VPN_GATEWAY])
        self.enabled = True
        print("[Routes] Full IPv4 VPN mode enabled")

    def disable_full_vpn(self):
        """Remove temporary full VPN routes. Missing routes are ignored."""
        self._run_route(["delete", "0.0.0.0", "mask", "128.0.0.0"], check=False)
        self._run_route(["delete", "128.0.0.0", "mask", "128.0.0.0"], check=False)
        if self.server_host:
            self._run_route(["delete", self.server_host], check=False)
        if self.enabled:
            print("[Routes] Full IPv4 VPN mode disabled")
        self.enabled = False

    def _run_route(self, args: List[str], check: bool = True):
        result = subprocess.run(
            ["route", *args],
            capture_output=True,
            text=True
        )
        if check and result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"route {' '.join(args)} failed: {error}")
        return result

    def _detect_default_gateway(self) -> Optional[str]:
        """Find the current IPv4 default gateway before installing VPN routes."""
        result = subprocess.run(
            ["route", "print", "-4", "0.0.0.0"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return None

        candidates: List[tuple[int, str]] = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway = parts[2]
                if gateway.lower() == "on-link":
                    continue
                try:
                    metric = int(parts[4])
                except ValueError:
                    metric = 9999
                candidates.append((metric, gateway))

        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]

    def _is_private_or_local(self, host: str) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return address.is_private or address.is_loopback or address.is_link_local


class ModernStyle:
    """Modern color scheme for the UI."""

    # Colors
    BG_PRIMARY = "#1a1a2e"      # Dark blue background
    BG_SECONDARY = "#16213e"    # Slightly lighter
    BG_CARD = "#0f3460"         # Card background
    BG_HOVER = "#1a4a7a"        # Hover state
    ACCENT = "#e94560"          # Red accent
    ACCENT_GREEN = "#00d26a"   # Connected green
    ACCENT_YELLOW = "#ffc107"  # Warning yellow
    TEXT_PRIMARY = "#ffffff"    # White text
    TEXT_SECONDARY = "#a0a0a0"  # Gray text
    BORDER = "#2a2a4a"          # Border color

    @classmethod
    def apply(cls, root: tk.Tk):
        """Apply modern style to the application."""
        style = ttk.Style()
        style.theme_use('clam')  # Use clam as base

        # Configure styles
        style.configure('TFrame', background=cls.BG_PRIMARY)
        style.configure('TLabel', background=cls.BG_PRIMARY, foreground=cls.TEXT_PRIMARY)
        style.configure('TButton', padding=10)
        style.configure('Card.TFrame', background=cls.BG_CARD)
        style.configure('Card.TLabel', background=cls.BG_CARD, foreground=cls.TEXT_PRIMARY)

        # Apply to root
        root.configure(bg=cls.BG_PRIMARY)


class ServerListFrame(ttk.Frame):
    """Frame containing the list of available servers."""

    def __init__(self, parent, servers: List[ServerInfo], on_select: Callable):
        super().__init__(parent)
        self.servers = servers
        self.on_select = on_select
        self.selected_index = None
        self.server_frames = []
        self.latency_labels: List[tk.Label] = []

        self._create_widgets()

    def _create_widgets(self):
        """Create server list widgets."""
        # Title
        title = ttk.Label(
            self,
            text="SELECT SERVER",
            font=('Segoe UI', 10, 'bold')
        )
        title.pack(pady=(10, 5), anchor='w')

        # Server list container with scrollbar
        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True)

        # Create server entries
        for i, server in enumerate(self.servers):
            frame = self._create_server_entry(container, server, i)
            frame.pack(fill=tk.X, pady=2)
            self.server_frames.append(frame)

    def _create_server_entry(self, parent: ttk.Frame, server: ServerInfo, index: int) -> ttk.Frame:
        """Create a single server entry."""
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.configure(style='Card.TFrame')

        # Make clickable
        frame.bind('<Button-1>', lambda e: self._on_server_click(index))
        frame.bind('<Enter>', lambda e: self._on_hover(frame, True))
        frame.bind('<Leave>', lambda e: self._on_hover(frame, False))

        # Flag and name
        flag = get_flag(server.region)
        name_text = f"{flag}  {server.name}"

        name_label = ttk.Label(
            frame,
            text=name_text,
            font=('Segoe UI', 11),
            style='Card.TLabel'
        )
        name_label.pack(side=tk.LEFT, padx=10, pady=8)
        name_label.bind('<Button-1>', lambda e: self._on_server_click(index))

        # Latency
        latency_text = self._get_latency_text(server.latency)
        latency_color = self._get_latency_color(server.latency)

        latency_label = tk.Label(
            frame,
            text=latency_text,
            font=('Segoe UI', 10),
            bg=ModernStyle.BG_CARD,
            fg=latency_color
        )
        latency_label.pack(side=tk.RIGHT, padx=10, pady=8)
        latency_label.bind('<Button-1>', lambda e: self._on_server_click(index))
        self.latency_labels.append(latency_label)

        return frame

    def _get_latency_text(self, latency: Optional[float]) -> str:
        """Format latency for display."""
        if latency is None:
            return "-- ms"
        return f"{latency:.0f} ms"

    def _get_latency_color(self, latency: Optional[float]) -> str:
        """Get color for latency display."""
        if latency is None:
            return ModernStyle.TEXT_SECONDARY
        if latency < 50:
            return ModernStyle.ACCENT_GREEN
        if latency < 150:
            return ModernStyle.ACCENT_YELLOW
        return ModernStyle.ACCENT

    def _on_server_click(self, index: int):
        """Handle server selection."""
        # Deselect previous
        if self.selected_index is not None:
            prev_frame = self.server_frames[self.selected_index]
            prev_frame.configure(style='Card.TFrame')

        # Select new
        self.selected_index = index
        frame = self.server_frames[index]
        # Highlight selected
        frame.configure(style='Card.TFrame')

        if self.on_select:
            self.on_select(self.servers[index])

    def _on_hover(self, frame: ttk.Frame, entering: bool):
        """Handle hover effect."""
        if entering:
            frame.configure(style='Card.TFrame')
        else:
            frame.configure(style='Card.TFrame')

    def update_latencies(self, latencies: Dict[str, float]):
        """Update latency displays."""
        for i, server in enumerate(self.servers):
            if server.host in latencies:
                server.latency = latencies[server.host]
                latency_text = self._get_latency_text(server.latency)
                latency_color = self._get_latency_color(server.latency)
                self.latency_labels[i].configure(text=latency_text, fg=latency_color)

    def refresh_servers(self, servers: List[ServerInfo]):
        """Refresh server list."""
        # Clear existing
        for widget in self.winfo_children():
            widget.destroy()

        self.servers = servers
        self.server_frames = []
        self.latency_labels = []
        self._create_widgets()


class StatusFrame(ttk.Frame):
    """Frame showing connection status and stats."""

    def __init__(self, parent):
        super().__init__(parent)

        self._create_widgets()

    def _create_widgets(self):
        """Create status widgets."""
        # Status indicator
        self.status_frame = ttk.Frame(self)
        self.status_frame.pack(fill=tk.X, pady=10)

        # Status dot
        self.status_canvas = tk.Canvas(
            self.status_frame,
            width=20,
            height=20,
            bg=ModernStyle.BG_PRIMARY,
            highlightthickness=0
        )
        self.status_canvas.pack(side=tk.LEFT, padx=(0, 10))
        self.status_dot = self.status_canvas.create_oval(5, 5, 15, 15, fill='gray', outline='')

        # Status text
        self.status_label = ttk.Label(
            self.status_frame,
            text="Disconnected",
            font=('Segoe UI', 14, 'bold')
        )
        self.status_label.pack(side=tk.LEFT)

        # Server info
        self.server_label = ttk.Label(
            self,
            text="No server selected",
            font=('Segoe UI', 10)
        )
        self.server_label.pack(anchor='w')

        # Duration
        self.duration_label = ttk.Label(
            self,
            text="Duration: 00:00:00",
            font=('Segoe UI', 10)
        )
        self.duration_label.pack(anchor='w')

        # Traffic stats
        self.traffic_label = ttk.Label(
            self,
            text="↑ 0 KB    ↓ 0 KB",
            font=('Segoe UI', 10)
        )
        self.traffic_label.pack(anchor='w', pady=(5, 0))

    def set_status(self, status: str, connected: bool = False):
        """Update connection status."""
        color = ModernStyle.ACCENT_GREEN if connected else ModernStyle.ACCENT
        self.status_canvas.itemconfig(self.status_dot, fill=color)
        self.status_label.configure(text=status)

    def set_server(self, server_name: str):
        """Update server name display."""
        self.server_label.configure(text=f"Server: {server_name}")

    def set_duration(self, duration: float):
        """Update duration display."""
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.duration_label.configure(text=f"Duration: {hours:02d}:{minutes:02d}:{seconds:02d}")

    def set_traffic(self, bytes_sent: int, bytes_received: int):
        """Update traffic stats display."""
        sent_str = self._format_bytes(bytes_sent)
        recv_str = self._format_bytes(bytes_received)
        self.traffic_label.configure(text=f"↑ {sent_str}    ↓ {recv_str}")

    def _format_bytes(self, num_bytes: int) -> str:
        """Format bytes to human readable string."""
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.1f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / 1024 / 1024:.1f} MB"
        else:
            return f"{num_bytes / 1024 / 1024 / 1024:.2f} GB"


class ControlFrame(ttk.Frame):
    """Frame with connect/disconnect button."""

    def __init__(self, parent, on_connect: Callable, on_disconnect: Callable):
        super().__init__(parent)
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self.is_connected = False
        self.full_vpn_var = tk.BooleanVar(value=False)

        self._create_widgets()

    def _create_widgets(self):
        """Create control widgets."""
        # Connect button
        self.connect_btn = tk.Button(
            self,
            text="CONNECT",
            font=('Segoe UI', 12, 'bold'),
            bg=ModernStyle.ACCENT_GREEN,
            fg='white',
            activebackground='#00a050',
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            command=self._on_click
        )
        self.connect_btn.pack(fill=tk.X, ipady=15, pady=10)

        self.full_vpn_check = ttk.Checkbutton(
            self,
            text="Full VPN mode (route all IPv4 traffic)",
            variable=self.full_vpn_var
        )
        self.full_vpn_check.pack(anchor='w', pady=(0, 5))

    def full_vpn_enabled(self) -> bool:
        """Return whether full IPv4 VPN routing is requested."""
        return self.full_vpn_var.get()

    def _on_click(self):
        """Handle button click."""
        if self.is_connected:
            self.on_disconnect()
        else:
            self.on_connect()

    def set_connected(self, connected: bool):
        """Update button state."""
        self.is_connected = connected
        if connected:
            self.connect_btn.configure(
                text="DISCONNECT",
                bg=ModernStyle.ACCENT
            )
            self.full_vpn_check.configure(state=tk.DISABLED)
        else:
            self.connect_btn.configure(
                text="CONNECT",
                bg=ModernStyle.ACCENT_GREEN
            )
            self.full_vpn_check.configure(state=tk.NORMAL)


class VPNApp:
    """Main VPN application."""

    def __init__(self):
        """Initialize the VPN application."""
        self.root = tk.Tk()
        self.root.title("MyVPN")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.resizable(False, False)

        # Apply modern style
        ModernStyle.apply(self.root)

        # Load configuration
        self.servers = self._load_servers()
        self.selected_server: Optional[ServerInfo] = None
        self.tunnel: Optional[TunnelClient] = None
        self.handshake_result: Optional[HandshakeResult] = None
        self.route_manager = WindowsRouteManager()

        # Connection state
        self.is_connecting = False
        self.full_vpn_requested = False
        self.start_time: Optional[float] = None

        # Stats update thread
        self.stats_thread: Optional[threading.Thread] = None
        self.stats_running = False

        # Create UI
        self._create_widgets()

        # Center window
        self._center_window()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start ping thread
        self._start_ping_thread()

    def _load_servers(self) -> List[ServerInfo]:
        """Load server configuration."""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
            return [ServerInfo.from_dict(s) for s in data.get('servers', [])]
        return []

    def _save_servers(self):
        """Save server configuration."""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump({
                'servers': [s.to_dict() for s in self.servers]
            }, f, indent=2)

    def _create_widgets(self):
        """Create all UI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 10))

        title = ttk.Label(
            header,
            text="🔒 MyVPN",
            font=('Segoe UI', 18, 'bold')
        )
        title.pack(side=tk.LEFT)

        # Settings button
        settings_btn = tk.Button(
            header,
            text="⚙️",
            font=('Segoe UI', 14),
            bg=ModernStyle.BG_PRIMARY,
            fg=ModernStyle.TEXT_PRIMARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self._show_settings
        )
        settings_btn.pack(side=tk.RIGHT)

        # Status frame
        self.status_frame = StatusFrame(main_frame)
        self.status_frame.pack(fill=tk.X, pady=10)

        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=10)

        # Server list
        self.server_list = ServerListFrame(
            main_frame,
            self.servers,
            on_select=self._on_server_select
        )
        self.server_list.pack(fill=tk.BOTH, expand=True, pady=10)

        # Control frame
        self.control_frame = ControlFrame(
            main_frame,
            on_connect=self._on_connect,
            on_disconnect=self._on_disconnect
        )
        self.control_frame.pack(fill=tk.X, pady=10)

        # Version label
        version_label = ttk.Label(
            main_frame,
            text="v1.0.0 | Built from scratch",
            font=('Segoe UI', 8),
            foreground=ModernStyle.TEXT_SECONDARY
        )
        version_label.pack(side=tk.BOTTOM, anchor='e')

    def _center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _start_ping_thread(self):
        """Start thread to ping servers."""
        def ping_servers():
            while self.root.winfo_exists():
                latencies = {}
                for server in self.servers:
                    if server.host:
                        latency = ping_server(server.host, server.port, timeout=1.0)
                        latencies[server.host] = latency
                        time.sleep(0.1)  # Don't flood

                # Update UI
                if self.root.winfo_exists():
                    self.root.after(0, lambda: self.server_list.update_latencies(latencies))

                time.sleep(30)  # Ping every 30 seconds

        thread = threading.Thread(target=ping_servers, daemon=True)
        thread.start()

    def _on_server_select(self, server: ServerInfo):
        """Handle server selection."""
        self.selected_server = server
        self.status_frame.set_server(server.name)
        print(f"[UI] Selected server: {server.name}")

    def _on_connect(self):
        """Handle connect button click."""
        server = self.selected_server
        if server is None:
            messagebox.showwarning("No Server Selected", "Please select a server first.")
            return

        if not server.pubkey and not server.allow_insecure:
            messagebox.showerror(
                "Server Key Required",
                "This server has no pinned public key.\n\n"
                "For secure use, set the server public key in settings.\n"
                "Only enable insecure mode for local testing."
            )
            return

        if not server.pubkey and server.allow_insecure:
            proceed = messagebox.askyesno(
                "Insecure Mode",
                "Insecure mode is enabled for this server.\n\n"
                "Server identity will not be verified, which allows MITM attacks.\n"
                "Continue only for local trusted testing."
            )
            if not proceed:
                return

        if self.is_connecting:
            return

        self.full_vpn_requested = self.control_frame.full_vpn_enabled()
        self.is_connecting = True
        self.status_frame.set_status("Connecting...", connected=False)
        self.control_frame.set_connected(False)

        # Connect in background thread
        thread = threading.Thread(target=self._connect_thread, daemon=True)
        thread.start()

    def _connect_thread(self):
        """Background thread for connection."""
        server = self.selected_server
        if server is None:
            self.root.after(0, lambda: self._on_connect_failed("No server selected"))
            return

        try:
            print(f"[UI] Connecting to {server.host}:{server.port}")

            # Perform handshake
            handshake = HandshakeClient(
                server_pubkey=server.pubkey,
                allow_insecure=server.allow_insecure
            )
            result = handshake.perform_handshake(
                server.host,
                server.handshake_port,
                timeout=10.0
            )

            self.handshake_result = result
            print(f"[UI] Handshake successful, UDP port: {result.udp_port}")

            # Create tunnel
            self.tunnel = TunnelClient(f"MyVPN_{server.region}")
            self.tunnel.set_state_callback(self._on_state_change)
            self.tunnel.set_stats_callback(self._on_stats_update)

            # Connect tunnel
            connected = self.tunnel.connect(
                server.host,
                result.udp_port,
                session_keys=result.session_keys
            )

            if connected:
                if self.full_vpn_requested:
                    self.route_manager.enable_full_vpn(server.host)
                self.start_time = time.time()
                self.root.after(0, lambda: self._on_connected())
            else:
                self.root.after(0, lambda: self._on_connect_failed("Failed to create tunnel"))

        except Exception as e:
            print(f"[UI] Connection error: {e}")
            self.root.after(0, lambda: self._on_connect_failed(str(e)))

    def _on_connected(self):
        """Called when connection succeeds."""
        self.is_connecting = False
        self.status_frame.set_status("Connected", connected=True)
        self.control_frame.set_connected(True)
        self._start_stats_thread()

    def _on_connect_failed(self, error: str):
        """Called when connection fails."""
        self.route_manager.disable_full_vpn()
        if self.tunnel:
            self.tunnel.disconnect()
            self.tunnel = None
        self.is_connecting = False
        self.status_frame.set_status("Connection Failed", connected=False)
        self.control_frame.set_connected(False)
        messagebox.showerror("Connection Failed", f"Could not connect to server.\n\n{error}")

    def _on_disconnect(self):
        """Handle disconnect button click."""
        self.route_manager.disable_full_vpn()
        if self.tunnel:
            self.tunnel.disconnect()
            self.tunnel = None

        self.handshake_result = None
        self.start_time = None
        self.stats_running = False

        self.status_frame.set_status("Disconnected", connected=False)
        self.control_frame.set_connected(False)

    def _on_close(self):
        """Clean up routes and tunnel before closing the UI."""
        self.route_manager.disable_full_vpn()
        if self.tunnel:
            self.tunnel.disconnect()
            self.tunnel = None
        self.stats_running = False
        self.root.destroy()

    def _on_state_change(self, state: TunnelState):
        """Handle tunnel state changes."""
        state_names = {
            TunnelState.DISCONNECTED: "Disconnected",
            TunnelState.CONNECTING: "Connecting...",
            TunnelState.CONNECTED: "Connected",
            TunnelState.DISCONNECTING: "Disconnecting...",
            TunnelState.ERROR: "Error"
        }

        def update():
            self.status_frame.set_status(state_names[state], state == TunnelState.CONNECTED)

        self.root.after(0, update)

    def _on_stats_update(self, stats: TunnelStats):
        """Handle stats updates from tunnel."""
        def update():
            if self.start_time:
                self.status_frame.set_duration(time.time() - self.start_time)
            self.status_frame.set_traffic(stats.bytes_sent, stats.bytes_received)

        self.root.after(0, update)

    def _start_stats_thread(self):
        """Start thread to update stats."""
        self.stats_running = True

        def update_loop():
            while self.stats_running and self.tunnel:
                if self.start_time:
                    duration = time.time() - self.start_time
                    self.root.after(0, lambda d=duration: self.status_frame.set_duration(d))
                time.sleep(1.0)

        self.stats_thread = threading.Thread(target=update_loop, daemon=True)
        self.stats_thread.start()

    def _show_settings(self):
        """Show settings dialog."""
        # Create settings window
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("380x560")
        settings_win.configure(bg=ModernStyle.BG_PRIMARY)
        settings_win.transient(self.root)
        settings_win.grab_set()

        # Title
        ttk.Label(
            settings_win,
            text="Settings",
            font=('Segoe UI', 14, 'bold')
        ).pack(pady=10)

        # Add server section
        add_frame = ttk.Frame(settings_win)
        add_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(add_frame, text="Add Server", font=('Segoe UI', 10, 'bold')).pack(anchor='w')

        # Name entry
        name_frame = ttk.Frame(add_frame)
        name_frame.pack(fill=tk.X, pady=5)
        ttk.Label(name_frame, text="Name:").pack(side=tk.LEFT)
        name_entry = ttk.Entry(name_frame)
        name_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

        # Host entry
        host_frame = ttk.Frame(add_frame)
        host_frame.pack(fill=tk.X, pady=5)
        ttk.Label(host_frame, text="Host:").pack(side=tk.LEFT)
        host_entry = ttk.Entry(host_frame)
        host_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

        # Port entry
        port_frame = ttk.Frame(add_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
        port_entry = ttk.Entry(port_frame)
        port_entry.insert(0, "51820")
        port_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

        # Handshake port entry
        handshake_port_frame = ttk.Frame(add_frame)
        handshake_port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(handshake_port_frame, text="HS Port:").pack(side=tk.LEFT)
        handshake_port_entry = ttk.Entry(handshake_port_frame)
        handshake_port_entry.insert(0, "51821")
        handshake_port_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

        # Region entry
        region_frame = ttk.Frame(add_frame)
        region_frame.pack(fill=tk.X, pady=5)
        ttk.Label(region_frame, text="Region:").pack(side=tk.LEFT)
        region_entry = ttk.Entry(region_frame)
        region_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

        # Server public key (hex)
        pubkey_frame = ttk.Frame(add_frame)
        pubkey_frame.pack(fill=tk.X, pady=5)
        ttk.Label(pubkey_frame, text="Pubkey:").pack(side=tk.LEFT)
        pubkey_entry = ttk.Entry(pubkey_frame)
        pubkey_entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

        # Insecure mode toggle (testing only)
        allow_insecure_var = tk.BooleanVar(value=False)
        insecure_check = ttk.Checkbutton(
            add_frame,
            text="Allow insecure (testing only)",
            variable=allow_insecure_var
        )
        insecure_check.pack(anchor='w', pady=5)

        # Existing server list section (with delete actions)
        ttk.Label(settings_win, text="Configured Servers", font=('Segoe UI', 10, 'bold')).pack(pady=10)

        list_frame = ttk.Frame(settings_win)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        # Scrollable list
        canvas = tk.Canvas(list_frame, bg=ModernStyle.BG_SECONDARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def render_servers():
            for widget in scrollable_frame.winfo_children():
                widget.destroy()

            if not self.servers:
                ttk.Label(
                    scrollable_frame,
                    text="No servers configured",
                    font=('Segoe UI', 10)
                ).pack(anchor='w', pady=2)
                return

            for idx, server in enumerate(self.servers):
                row = ttk.Frame(scrollable_frame)
                row.pack(fill=tk.X, pady=2)

                server_label = ttk.Label(
                    row,
                    text=(
                        f"{get_flag(server.region)} {server.name}  "
                        f"{server.host}:{server.port}  hs:{server.handshake_port}"
                    ),
                    font=('Segoe UI', 9)
                )
                server_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

                def delete_server(i=idx):
                    deleting_selected = (
                        self.selected_server is not None and
                        i < len(self.servers) and
                        self.selected_server is self.servers[i]
                    )
                    del self.servers[i]
                    if deleting_selected:
                        self.selected_server = None
                        self.status_frame.set_server("No server selected")
                    self._save_servers()
                    self.server_list.refresh_servers(self.servers)
                    render_servers()

                ttk.Button(row, text="Delete", command=delete_server).pack(side=tk.RIGHT)

        # Add button
        def add_server():
            try:
                pubkey = None
                pubkey_text = pubkey_entry.get().strip()
                if pubkey_text:
                    try:
                        pubkey = bytes.fromhex(pubkey_text)
                    except ValueError as exc:
                        raise ValueError("Public key must be valid hex") from exc
                    if len(pubkey) != 32:
                        raise ValueError("Public key must be 32 bytes (64 hex chars)")

                tunnel_port = int(port_entry.get() or 51820)
                hs_port_text = handshake_port_entry.get().strip()
                handshake_port = int(hs_port_text) if hs_port_text else tunnel_port + 1

                server = ServerInfo(
                    name=name_entry.get() or "Custom Server",
                    host=host_entry.get() or "127.0.0.1",
                    port=tunnel_port,
                    handshake_port=handshake_port,
                    pubkey=pubkey,
                    region=region_entry.get() or "default",
                    allow_insecure=allow_insecure_var.get()
                )
                self.servers.append(server)
                self._save_servers()
                self.server_list.refresh_servers(self.servers)
                render_servers()
                name_entry.delete(0, tk.END)
                host_entry.delete(0, tk.END)
                host_entry.insert(0, "127.0.0.1")
                port_entry.delete(0, tk.END)
                port_entry.insert(0, "51820")
                handshake_port_entry.delete(0, tk.END)
                handshake_port_entry.insert(0, "51821")
                region_entry.delete(0, tk.END)
                pubkey_entry.delete(0, tk.END)
                allow_insecure_var.set(False)
            except ValueError as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(add_frame, text="Add Server", command=add_server).pack(pady=10)
        render_servers()

        # Close button
        ttk.Button(settings_win, text="Close", command=settings_win.destroy).pack(pady=10)

    def run(self):
        """Run the application."""
        self.root.mainloop()


def run_app():
    """Run the VPN application."""
    app = VPNApp()
    app.run()


if __name__ == "__main__":
    run_app()
