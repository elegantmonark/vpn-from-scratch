"""
NAT/Routing setup for VPN server.
Configures Windows routing to allow VPN clients to access the internet.
"""

import os
import sys
import subprocess
import platform
from typing import List, Optional


class NATManager:
    """
    Manages Network Address Translation for VPN server.
    Allows VPN clients to access the internet through the server.
    """

    def __init__(self, tun_name: str = "VPNServer", subnet: str = "10.0.0.0/24"):
        """
        Initialize NAT manager.

        Args:
            tun_name: Name of the TUN interface
            subnet: VPN client subnet
        """
        self.tun_name = tun_name
        self.subnet = subnet
        self.platform = platform.system()

    def setup(self) -> bool:
        """
        Set up NAT routing.

        Returns:
            True if successful
        """
        if self.platform == "Windows":
            return self._setup_windows()
        else:
            return self._setup_linux()

    def teardown(self) -> bool:
        """
        Remove NAT routing.

        Returns:
            True if successful
        """
        if self.platform == "Windows":
            return self._teardown_windows()
        else:
            return self._teardown_linux()

    def _setup_windows(self) -> bool:
        """
        Set up Windows NAT using netsh or PowerShell.

        Requires Administrator privileges.
        """
        print(f"[NAT] Setting up Windows NAT for {self.tun_name}...")

        commands = [
            # Enable IP forwarding (requires registry edit on Windows)
            # reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v IPEnableRouter /t REG_DWORD /d 1 /f

            # Add NAT interface
            f'netsh routing ip nat add interface "{self.tun_name}" full',
        ]

        # Find the main network interface
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True
            )

            # Look for connected Ethernet/Wi-Fi interface
            lines = result.stdout.split('\n')
            for line in lines:
                if 'connected' in line.lower() and ('ethernet' in line.lower() or 'wi-fi' in line.lower()):
                    parts = line.split()
                    if len(parts) >= 5:
                        iface_name = ' '.join(parts[4:])
                        commands.append(f'netsh routing ip nat add interface "{iface_name}" private')
                        break

        except Exception as e:
            print(f"[NAT] Warning: Could not detect network interface: {e}")

        success = True
        for cmd in commands:
            print(f"  $ {cmd}")
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"  Failed: {e}")
                success = False

        if not success:
            print("\n[NAT] Windows NAT setup requires Administrator privileges.")
            print("[NAT] Run this command as Administrator:")
            print(f'  netsh routing ip nat install')
            print(f'  netsh routing ip nat add interface "{self.tun_name}" full')
            print(f'  netsh routing ip nat add interface "Ethernet" private')

        return success

    def _teardown_windows(self) -> bool:
        """Remove Windows NAT."""
        commands = [
            f'netsh routing ip nat delete interface "{self.tun_name}"',
        ]

        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            except:
                pass

        return True

    def _setup_linux(self) -> bool:
        """
        Set up Linux NAT using iptables.

        Requires root privileges.
        """
        print(f"[NAT] Setting up Linux NAT for {self.tun_name}...")

        # Find main interface
        main_iface = self._get_main_interface()

        commands = [
            # Enable IP forwarding
            "sysctl -w net.ipv4.ip_forward=1",

            # Flush existing NAT rules for VPN subnet
            f"iptables -t nat -D POSTROUTING -s {self.subnet} -o {main_iface} -j MASQUERADE 2>/dev/null || true",

            # Add NAT rule
            f"iptables -t nat -A POSTROUTING -s {self.subnet} -o {main_iface} -j MASQUERADE",

            # Allow forwarding
            f"iptables -A FORWARD -i {self.tun_name} -o {main_iface} -j ACCEPT",
            f"iptables -A FORWARD -i {main_iface} -o {self.tun_name} -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]

        success = True
        for cmd in commands:
            print(f"  $ {cmd}")
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"  Failed: {e}")
                success = False

        if not success:
            print("\n[NAT] NAT setup requires root privileges.")
            print("[NAT] Run with sudo or as root.")

        return success

    def _teardown_linux(self) -> bool:
        """Remove Linux NAT."""
        main_iface = self._get_main_interface()

        commands = [
            f"iptables -t nat -D POSTROUTING -s {self.subnet} -o {main_iface} -j MASQUERADE",
            f"iptables -D FORWARD -i {self.tun_name} -o {main_iface} -j ACCEPT",
            f"iptables -D FORWARD -i {main_iface} -o {self.tun_name} -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]

        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, capture_output=True)
            except:
                pass

        return True

    def _get_main_interface(self) -> str:
        """Get the main network interface name."""
        try:
            # Try to find default route interface
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except:
            pass

        # Fallback
        return "eth0"


class KillSwitch:
    """
    Kill switch implementation.
    Blocks all non-VPN traffic when the tunnel is down.
    """

    def __init__(self, tun_name: str = "MyVPN", vpn_port: int = 51820):
        """
        Initialize kill switch.

        Args:
            tun_name: Name of the TUN interface
            vpn_port: VPN server port (excluded from block)
        """
        self.tun_name = tun_name
        self.vpn_port = vpn_port
        self.platform = platform.system()
        self._enabled = False

    def enable(self, server_host: Optional[str] = None) -> bool:
        """
        Enable kill switch.
        Blocks all traffic except VPN and essential services.

        Args:
            server_host: VPN server host to exclude from block

        Returns:
            True if successful
        """
        if self._enabled:
            return True

        print(f"[KillSwitch] Enabling kill switch...")

        if self.platform == "Windows":
            success = self._enable_windows(server_host)
        else:
            success = self._enable_linux(server_host)

        if success:
            self._enabled = True
            print("[KillSwitch] Enabled - all non-VPN traffic blocked")

        return success

    def disable(self) -> bool:
        """
        Disable kill switch.
        Restores normal network access.

        Returns:
            True if successful
        """
        if not self._enabled:
            return True

        print("[KillSwitch] Disabling kill switch...")

        if self.platform == "Windows":
            success = self._disable_windows()
        else:
            success = self._disable_linux()

        if success:
            self._enabled = False
            print("[KillSwitch] Disabled - normal network access restored")

        return success

    def _enable_windows(self, server_host: Optional[str]) -> bool:
        """
        Enable kill switch on Windows using Windows Firewall.

        Requires Administrator privileges.
        """
        commands = []

        # Block all outbound traffic
        commands.append(
            'netsh advfirewall firewall add rule name="VPN Kill Switch" '
            'dir=out action=block enable=yes'
        )

        # Allow VPN traffic
        commands.append(
            f'netsh advfirewall firewall add rule name="VPN Allow" '
            f'dir=out action=allow protocol=UDP localport={self.vpn_port}'
        )

        # Allow DNS
        commands.append(
            'netsh advfirewall firewall add rule name="VPN DNS" '
            'dir=out action=allow protocol=UDP remoteport=53'
        )

        # Allow VPN server IP if specified
        if server_host:
            commands.append(
                f'netsh advfirewall firewall add rule name="VPN Server" '
                f'dir=out action=allow remoteip={server_host}'
            )

        success = True
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"[KillSwitch] Failed: {e}")
                success = False

        if not success:
            print("\n[KillSwitch] Windows Firewall requires Administrator privileges.")

        return success

    def _disable_windows(self) -> bool:
        """Disable kill switch on Windows."""
        commands = [
            'netsh advfirewall firewall delete rule name="VPN Kill Switch"',
            'netsh advfirewall firewall delete rule name="VPN Allow"',
            'netsh advfirewall firewall delete rule name="VPN DNS"',
            'netsh advfirewall firewall delete rule name="VPN Server"',
        ]

        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, capture_output=True)
            except:
                pass

        return True

    def _enable_linux(self, server_host: Optional[str]) -> bool:
        """
        Enable kill switch on Linux using iptables.

        Requires root privileges.
        """
        commands = [
            # Mark VPN traffic
            f"iptables -t mangle -A OUTPUT -p udp --dport {self.vpn_port} -j MARK --set-mark 0x1",

            # Block all non-VPN traffic (except marked)
            "iptables -A OUTPUT ! -o lo -m mark ! --mark 0x1 -j DROP",

            # Allow DNS
            "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
            "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
        ]

        # Allow VPN server IP
        if server_host:
            commands.insert(1, f"iptables -A OUTPUT -d {server_host} -j ACCEPT")

        success = True
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"[KillSwitch] Failed: {e}")
                success = False

        if not success:
            print("\n[KillSwitch] iptables requires root privileges.")

        return success

    def _disable_linux(self) -> bool:
        """Disable kill switch on Linux."""
        commands = [
            f"iptables -t mangle -D OUTPUT -p udp --dport {self.vpn_port} -j MARK --set-mark 0x1",
            "iptables -D OUTPUT ! -o lo -m mark ! --mark 0x1 -j DROP",
            "iptables -D OUTPUT -p udp --dport 53 -j ACCEPT",
            "iptables -D OUTPUT -p tcp --dport 53 -j ACCEPT",
        ]

        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, capture_output=True)
            except:
                pass

        return True

    @property
    def enabled(self) -> bool:
        """Check if kill switch is enabled."""
        return self._enabled


# Test and demonstration
if __name__ == "__main__":
    print("NAT Manager and Kill Switch Demo")
    print("=" * 40)

    nat = NATManager()
    killswitch = KillSwitch()

    print(f"\nPlatform: {platform.system()}")
    print(f"TUN interface: {nat.tun_name}")
    print(f"VPN subnet: {nat.subnet}")
    print(f"VPN port: {killswitch.vpn_port}")

    print("\nCommands to run (requires admin/root):")
    print("\n--- NAT Setup ---")
    if platform.system() == "Windows":
        print("  netsh routing ip nat install")
        print(f"  netsh routing ip nat add interface \"{nat.tun_name}\" full")
        print("  netsh routing ip nat add interface \"Ethernet\" private")
    else:
        print("  sysctl -w net.ipv4.ip_forward=1")
        print(f"  iptables -t nat -A POSTROUTING -s {nat.subnet} -o eth0 -j MASQUERADE")

    print("\n--- Kill Switch ---")
    if platform.system() == "Windows":
        print("  # Block all outbound")
        print("  netsh advfirewall firewall add rule name=\"VPN Kill Switch\" dir=out action=block")
        print("  # Allow VPN traffic")
        print(f"  netsh advfirewall firewall add rule name=\"VPN Allow\" dir=out action=allow protocol=UDP localport={killswitch.vpn_port}")
    else:
        print("  iptables -A OUTPUT ! -o tun0 -m mark ! --mark 0x1 -j DROP")
        print(f"  iptables -t mangle -A OUTPUT -p udp --dport {killswitch.vpn_port} -j MARK --set-mark 0x1")