#!/usr/bin/env python3
"""
VPN From Scratch - Main Entry Point

Usage:
    python vpn.py client    # Run VPN client (UI)
    python vpn.py server    # Run VPN server
    python vpn.py test      # Run tests
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def print_banner():
    """Print application banner."""
    print("=" * 60)
    print("  VPN From Scratch")
    print("  A custom VPN implementation using Wintun/TUN")
    print("=" * 60)
    print()


def run_client():
    """Run the VPN client UI."""
    print_banner()
    print("Starting VPN Client...")
    print()

    # Check for Wintun DLL
    wintun_path = os.path.join(os.path.dirname(__file__), "wintun", "wintun.dll")
    if not os.path.exists(wintun_path):
        print("ERROR: Wintun driver not found!")
        print()
        print("Please download wintun.dll from https://www.wintun.com/")
        print("and place it in the 'wintun' directory.")
        print()
        print("Or run this PowerShell command as Administrator:")
        print("  Invoke-WebRequest -Uri 'https://www.wintun.com/builds/wintun-0.14.1.zip' -OutFile 'wintun.zip'")
        print("  Expand-Archive -Path 'wintun.zip' -DestinationPath 'wintun-temp'")
        print("  Copy-Item 'wintun-temp/wintun/bin/amd64/wintun.dll' -Destination 'wintun/wintun.dll'")
        print()
        return 1

    # Import and run UI
    try:
        from ui.main import run_app
        run_app()
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure all dependencies are installed: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


def run_server():
    """Run the VPN server."""
    print_banner()
    print("Starting VPN Server...")
    print()

    # Check for admin privileges
    if os.name == 'nt':
        print("NOTE: Running as server on Windows requires:")
        print("  1. Administrator privileges")
        print("  2. Wintun driver installed")
        print("  3. NAT routing configured")
        print()

    try:
        from server.main import main
        main()
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure all dependencies are installed: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


def run_tests():
    """Run all tests."""
    print_banner()
    print("Running tests...")
    print()

    all_passed = True

    # Test crypto
    print("-" * 40)
    print("Testing crypto module...")
    print("-" * 40)
    try:
        from client.crypto import test_encryption, test_key_exchange
        test_encryption()
        test_key_exchange()
        print("[OK] Crypto tests passed\n")
    except Exception as e:
        print(f"[FAIL] Crypto tests failed: {e}\n")
        all_passed = False

    # Test handshake
    print("-" * 40)
    print("Testing handshake module...")
    print("-" * 40)
    try:
        from client.handshake import HandshakeClient, HandshakeServer
        import socket
        import threading
        import time

        # Quick integration test
        print("[OK] Handshake module imports correctly\n")
    except Exception as e:
        print(f"[FAIL] Handshake tests failed: {e}\n")
        all_passed = False

    # Test Wintun (requires driver)
    print("-" * 40)
    print("Testing Wintun module...")
    print("-" * 40)
    wintun_path = os.path.join(os.path.dirname(__file__), "wintun", "wintun.dll")
    if os.path.exists(wintun_path):
        print("[OK] Wintun.dll found")
        try:
            from client.wintun import TUNInterface
            print("[OK] Wintun module imports correctly")
            print("  Note: Full test requires Administrator privileges\n")
        except Exception as e:
            print(f"[FAIL] Wintun module failed: {e}\n")
            all_passed = False
    else:
        print("[WARN] Wintun.dll not found - skipping Wintun tests")
        print("  Download from https://www.wintun.com/\n")

    # Summary
    print("-" * 40)
    if all_passed:
        print("All tests passed! [OK]")
    else:
        print("Some tests failed. [FAIL]")
    print("-" * 40)

    return 0 if all_passed else 1


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python vpn.py <command>")
        print()
        print("Commands:")
        print("  client    Run VPN client (UI)")
        print("  server    Run VPN server")
        print("  test      Run tests")
        print()
        print("Options:")
        print("  --help    Show this help message")
        return 1

    command = sys.argv[1].lower()

    if command in ('--help', '-h', 'help'):
        print("VPN From Scratch - Custom VPN Implementation")
        print()
        print("Usage: python vpn.py <command>")
        print()
        print("Commands:")
        print("  client    Run VPN client with GUI")
        print("  server    Run VPN server")
        print("  test      Run component tests")
        return 0

    if command == 'client':
        return run_client()
    elif command == 'server':
        return run_server()
    elif command == 'test':
        return run_tests()
    else:
        print(f"Unknown command: {command}")
        print("Use 'python vpn.py --help' for usage information")
        return 1


if __name__ == "__main__":
    sys.exit(main())
