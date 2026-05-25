"""
Wintun TUN interface wrapper for Windows.
Uses ctypes to interact with the Wintun driver DLL.

Wintun API documentation: https://www.wintun.com/
"""

import ctypes
import ctypes.wintypes
import os
import subprocess
import threading
from pathlib import Path
from typing import Optional

# Wintun constants
WINTUN_MAX_POOL = 256
ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2


class WintunAdapter:
    """Wrapper for Wintun driver - creates TUN interface on Windows."""

    def __init__(self, dll_path: Optional[str] = None):
        """
        Load Wintun DLL and prepare for adapter creation.
        """
        self.dll_path = self._find_dll(dll_path)
        self.dll = ctypes.WinDLL(self.dll_path, use_last_error=True)
        self._setup_functions()
        self.adapter = None
        self.session = None
        self._lock = threading.RLock()

    def _find_dll(self, dll_path: Optional[str]) -> str:
        """Find wintun.dll in common locations."""
        if dll_path and os.path.exists(dll_path):
            return dll_path

        search_paths = [
            Path(__file__).parent.parent / "wintun" / "wintun.dll",
            Path(__file__).parent.parent / "wintun.dll",
            Path(__file__).parent / "wintun.dll",
            Path(os.environ.get("SYSTEMROOT", "C:\\Windows")) / "System32" / "wintun.dll",
        ]

        for path in search_paths:
            if path.exists():
                return str(path)

        raise FileNotFoundError(
            f"Wintun DLL not found. Download from https://www.wintun.com/ "
            f"and place wintun.dll in the 'wintun' directory."
        )

    def _setup_functions(self):
        """Set up ctypes function signatures for Wintun API."""
        # WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID* RequestedGUID)
        self._WintunCreateAdapter = self.dll.WintunCreateAdapter
        self._WintunCreateAdapter.argtypes = [
            ctypes.c_wchar_p,  # Name
            ctypes.c_wchar_p,  # TunnelType
            ctypes.c_void_p,   # RequestedGUID (can be NULL)
        ]
        self._WintunCreateAdapter.restype = ctypes.c_void_p

        # WintunOpenAdapter(LPCWSTR Name)
        self._WintunOpenAdapter = self.dll.WintunOpenAdapter
        self._WintunOpenAdapter.argtypes = [ctypes.c_wchar_p]
        self._WintunOpenAdapter.restype = ctypes.c_void_p

        # WintunCloseAdapter(HANDLE Adapter)
        self._WintunCloseAdapter = self.dll.WintunCloseAdapter
        self._WintunCloseAdapter.argtypes = [ctypes.c_void_p]
        self._WintunCloseAdapter.restype = None

        # WintunStartSession(HANDLE Adapter, DWORD Capacity)
        self._WintunStartSession = self.dll.WintunStartSession
        self._WintunStartSession.argtypes = [
            ctypes.c_void_p,  # Adapter handle
            ctypes.c_uint32,  # Ring capacity
        ]
        self._WintunStartSession.restype = ctypes.c_void_p  # Returns session handle

        # WintunEndSession(HANDLE Session)
        self._WintunEndSession = self.dll.WintunEndSession
        self._WintunEndSession.argtypes = [ctypes.c_void_p]
        self._WintunEndSession.restype = None

        # WintunGetReadWaitEvent(HANDLE Session)
        self._WintunGetReadWaitEvent = self.dll.WintunGetReadWaitEvent
        self._WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]
        self._WintunGetReadWaitEvent.restype = ctypes.c_void_p

        # WintunReceivePacket(HANDLE Session, DWORD* PacketSize)
        self._WintunReceivePacket = self.dll.WintunReceivePacket
        self._WintunReceivePacket.argtypes = [
            ctypes.c_void_p,  # Session handle
            ctypes.POINTER(ctypes.c_uint32),  # Out: Packet size
        ]
        self._WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        # WintunReleaseReceivePacket(HANDLE Session, const BYTE* Packet)
        self._WintunReleaseReceivePacket = self.dll.WintunReleaseReceivePacket
        self._WintunReleaseReceivePacket.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self._WintunReleaseReceivePacket.restype = None

        # WintunAllocateSendPacket(HANDLE Session, DWORD PacketSize)
        self._WintunAllocateSendPacket = self.dll.WintunAllocateSendPacket
        self._WintunAllocateSendPacket.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        # WintunSendPacket(HANDLE Session, BYTE* Packet)
        self._WintunSendPacket = self.dll.WintunSendPacket
        self._WintunSendPacket.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self._WintunSendPacket.restype = None

        # WintunGetRunningDriverVersion()
        self._WintunGetRunningDriverVersion = self.dll.WintunGetRunningDriverVersion
        self._WintunGetRunningDriverVersion.argtypes = []
        self._WintunGetRunningDriverVersion.restype = ctypes.c_uint32

    def get_driver_version(self) -> int:
        """Get running Wintun driver version."""
        return self._WintunGetRunningDriverVersion()

    def create_adapter(self, name: str = "MyVPN", pool: str = "WireGuard") -> bool:
        """Create a new Wintun adapter."""
        with self._lock:
            if self.adapter:
                return True

            self.adapter = self._WintunCreateAdapter(
                ctypes.c_wchar_p(name),
                ctypes.c_wchar_p(pool),
                None
            )
            self.adapter_name = name

            if not self.adapter:
                # If adapter already exists, open it by name.
                self.adapter = self._WintunOpenAdapter(ctypes.c_wchar_p(name))
                if not self.adapter:
                    err = ctypes.get_last_error()
                    raise RuntimeError(
                        f"Failed to create/open Wintun adapter '{name}' (WinError={err}). "
                        f"Run as Administrator and ensure wintun.dll matches platform architecture."
                    )

            print(f"[Wintun] Created adapter: {name} (handle: {self.adapter})")
            return True

    def start_session(self, ring_capacity: int = 0x400000) -> bool:
        """Start a Wintun session for reading/writing packets."""
        with self._lock:
            if not self.adapter:
                raise RuntimeError("No adapter created. Call create_adapter() first.")

            if self.session:
                return True

            self.session = self._WintunStartSession(self.adapter, ring_capacity)

            if not self.session:
                raise RuntimeError("Failed to start Wintun session")

            print(f"[Wintun] Session started (ring buffer: {ring_capacity // 1024 // 1024}MB)")
            return True

    def stop_session(self):
        """Stop the Wintun session."""
        with self._lock:
            if self.session:
                self._WintunEndSession(self.session)
                self.session = None
                print("[Wintun] Session stopped")

    def close_adapter(self):
        """Close and remove the Wintun adapter."""
        with self._lock:
            self.stop_session()
            if self.adapter:
                self._WintunCloseAdapter(self.adapter)
                self.adapter = None
                print("[Wintun] Adapter closed")

    def read_packet(self, timeout_ms: int = 5000) -> Optional[bytes]:
        """Read a packet from the TUN interface."""
        if not self.session:
            raise RuntimeError("No active session")

        size = ctypes.c_uint32()
        packet_ptr = self._WintunReceivePacket(self.session, ctypes.byref(size))

        if not packet_ptr:
            return None

        # Copy packet data
        packet_data = bytes(ctypes.string_at(packet_ptr, size.value))

        # Release buffer
        self._WintunReleaseReceivePacket(self.session, packet_ptr)

        return packet_data

    def write_packet(self, data: bytes) -> bool:
        """Write a packet to the TUN interface."""
        if not self.session:
            raise RuntimeError("No active session")

        if len(data) == 0:
            return False

        packet_ptr = self._WintunAllocateSendPacket(self.session, len(data))
        if not packet_ptr:
            err = ctypes.get_last_error()
            raise RuntimeError(f"Failed to allocate send packet buffer (WinError={err})")

        ctypes.memmove(packet_ptr, data, len(data))
        self._WintunSendPacket(self.session, packet_ptr)
        return True

    def __enter__(self):
        self.create_adapter()
        self.start_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_adapter()
        return False


class TUNInterface:
    """Cross-platform TUN interface wrapper."""

    def __init__(self, name: str = "MyVPN"):
        self.name = name
        self._impl = None
        self._platform = None

        if os.name == 'nt':
            self._platform = 'windows'
            self._impl = WintunAdapter()
        else:
            self._platform = 'linux'
            self._impl = self._create_linux_tun(name)

    def _create_linux_tun(self, name: str):
        import fcntl
        import struct

        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        tun_fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

        return {'fd': tun_fd, 'name': name}

    def create(self) -> bool:
        if self._platform == 'windows':
            return self._impl.create_adapter(self.name)
        return True

    def start(self) -> bool:
        if self._platform == 'windows':
            return self._impl.start_session()
        return True

    def configure(self, address: str, netmask: str = "255.255.255.0") -> bool:
        """Assign an IP address and bring the TUN interface up."""
        if self._platform == 'windows':
            return self._configure_windows(address, netmask)
        return self._configure_linux(address)

    def _configure_windows(self, address: str, netmask: str) -> bool:
        commands = [
            ["netsh", "interface", "ip", "set", "address", f"name={self.name}", "static", address, netmask],
            ["netsh", "interface", "set", "interface", self.name, "admin=enabled"],
        ]

        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(
                    f"Failed to configure Windows TUN interface '{self.name}': "
                    f"{result.stderr.strip() or result.stdout.strip()}"
                )

        print(f"[TUN] Configured {self.name} with {address}/{netmask}")
        return True

    def _configure_linux(self, address_cidr: str) -> bool:
        name = self._impl['name']
        commands = [
            ["ip", "addr", "flush", "dev", name],
            ["ip", "addr", "add", address_cidr, "dev", name],
            ["ip", "link", "set", "dev", name, "up"],
        ]

        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(
                    f"Failed to configure Linux TUN interface '{name}': "
                    f"{result.stderr.strip() or result.stdout.strip()}"
                )

        print(f"[TUN] Configured {name} with {address_cidr}")
        return True

    def stop(self):
        if self._platform == 'windows':
            self._impl.stop_session()
        elif self._impl:
            os.close(self._impl['fd'])

    def close(self):
        if self._platform == 'windows':
            self._impl.close_adapter()
        elif self._impl:
            os.close(self._impl['fd'])
            self._impl = None

    def read(self, timeout_ms: int = 5000) -> Optional[bytes]:
        if self._platform == 'windows':
            return self._impl.read_packet(timeout_ms)
        else:
            import select
            ready, _, _ = select.select([self._impl['fd']], [], [], timeout_ms / 1000)
            if ready:
                return os.read(self._impl['fd'], 65535)
            return None

    def write(self, data: bytes) -> bool:
        if self._platform == 'windows':
            return self._impl.write_packet(data)
        else:
            os.write(self._impl['fd'], data)
            return True

    def __enter__(self):
        self.create()
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


if __name__ == "__main__":
    print("Testing Wintun adapter...")

    try:
        with TUNInterface("TestVPN") as tun:
            print(f"\nTUN interface '{tun.name}' is ready!")
            print("\nTo capture packets, run this in another terminal:")
            print("  ping 10.0.0.1")
            print("\nWaiting 5 seconds for packets...")

            import time
            for i in range(5):
                packet = tun.read(1000)
                if packet:
                    print(f"\n  Packet received: {len(packet)} bytes")
                    print(f"  Hex: {packet[:20].hex()}")
                else:
                    print(f"  Waiting... ({i+1}/5)")

            print("\nTest complete!")

    except Exception as e:
        print(f"\nError: {e}")
        print("\nNote: This requires Administrator privileges on Windows.")
