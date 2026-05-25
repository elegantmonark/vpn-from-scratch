#!/usr/bin/env python3
r"""
Test script for Wintun TUN interface.
MUST be run as Administrator!

Usage:
  Right-click PowerShell -> Run as Administrator
  cd path/to/vpn-project
  python test_tun.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client.wintun import TUNInterface

def main():
    print("=" * 50)
    print("Wintun TUN Interface Test")
    print("=" * 50)
    print()

    # Check if running as admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("ERROR: Not running as Administrator!")
            print()
            print("Please right-click PowerShell and select:")
            print("  'Run as administrator'")
            print()
            print("Then run:")
            print("  cd path/to/vpn-project")
            print("  python test_tun.py")
            return 1
    except:
        pass

    try:
        print("Creating TUN interface 'TestVPN'...")
        tun = TUNInterface("TestVPN")
        tun.create()
        print("[OK] TUN interface created")
        print()

        print("Starting session...")
        tun.start()
        print("[OK] Session started")
        print()

        print("TUN interface is ready!")
        print()
        print("In another terminal, try:")
        print("  ping 10.0.0.1")
        print()
        print("Watching for packets (10 seconds)...")
        print("-" * 50)

        import time
        packets_seen = 0
        for i in range(10):
            packet = tun.read(1000)
            if packet:
                packets_seen += 1
                # Parse IP packet header
                if len(packet) >= 20:
                    version = packet[0] >> 4
                    protocol = packet[9] if version == 4 else packet[6]
                    proto_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                    proto = proto_names.get(protocol, f'{protocol}')
                    print(f"  [{packets_seen}] IPv{version} {proto}: {len(packet)} bytes")
                else:
                    print(f"  [{packets_seen}] Unknown: {len(packet)} bytes")
            else:
                print(f"  Waiting... ({i+1}/10)")

        print("-" * 50)
        print()

        if packets_seen == 0:
            print("No packets captured.")
            print("To test, open another terminal and run: ping 10.0.0.1")

        tun.close()
        print("[OK] TUN interface closed")
        return 0

    except Exception as e:
        import traceback
        print()
        print("[FAILED]")
        print("-" * 50)
        traceback.print_exc()
        print("-" * 50)
        return 1


if __name__ == "__main__":
    sys.exit(main())
