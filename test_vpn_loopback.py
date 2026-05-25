#!/usr/bin/env python3
"""
Test VPN encryption + handshake + UDP tunnel without TUN interface.
This tests all the VPN components except the actual network capture.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket
import threading
import time
import secrets

from client.crypto import CryptoManager, KeyExchange, SessionKeys, generate_keypair
from client.handshake import HandshakeClient, HandshakeServer, HANDSHAKE_PORT
from client.tunnel import TunnelServer


def test_encryption():
    """Test AES-256-GCM encryption."""
    print("\n" + "=" * 50)
    print("TEST 1: AES-256-GCM Encryption")
    print("=" * 50)

    import secrets
    key = secrets.token_bytes(32)
    crypto = CryptoManager(key)

    # Test encryption/decryption
    messages = [
        b"Hello, VPN!",
        b"A" * 1000,  # Large message
        b"",  # Empty message
        secrets.token_bytes(1500),  # Random data
    ]

    for msg in messages:
        encrypted = crypto.encrypt(msg)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == msg, f"Decryption mismatch for {len(msg)} byte message"
        print(f"  [OK] {len(msg)} bytes -> {len(encrypted)} bytes encrypted")

    print("\nEncryption test PASSED!")
    return True


def test_key_exchange():
    """Test X25519 key exchange."""
    print("\n" + "=" * 50)
    print("TEST 2: X25519 Key Exchange")
    print("=" * 50)

    # Alice and Bob exchange keys
    alice = KeyExchange()
    bob = KeyExchange()

    alice_pub = alice.get_public_key_bytes()
    bob_pub = bob.get_public_key_bytes()

    print(f"  Alice public key: {alice_pub[:8].hex()}...")
    print(f"  Bob public key:   {bob_pub[:8].hex()}...")

    # Derive session keys
    nonce = secrets.token_bytes(12)
    alice_keys = alice.derive_session_keys(bob_pub, nonce)
    bob_keys = bob.derive_session_keys(alice_pub, nonce)

    # Keys should be swapped (Alice's encrypt = Bob's decrypt)
    assert alice_keys.encrypt_key == bob_keys.decrypt_key, "Encrypt key mismatch!"
    assert alice_keys.decrypt_key == bob_keys.encrypt_key, "Decrypt key mismatch!"

    print(f"  [OK] Keys derived correctly")
    print(f"  Alice encrypt key: {alice_keys.encrypt_key[:8].hex()}...")
    print(f"  Bob decrypt key:   {bob_keys.decrypt_key[:8].hex()}...")

    # Test cross-party encryption
    alice_crypto = CryptoManager(alice_keys.encrypt_key)
    bob_crypto = CryptoManager(bob_keys.decrypt_key)

    msg = b"Secret message from Alice"
    encrypted = alice_crypto.encrypt(msg)
    decrypted = bob_crypto.decrypt(encrypted)
    assert decrypted == msg, "Cross-party decryption failed!"

    print(f"  [OK] Cross-party encryption works")

    print("\nKey exchange test PASSED!")
    return True


def test_udp_tunnel():
    """Test UDP packet forwarding with encryption."""
    print("\n" + "=" * 50)
    print("TEST 3: UDP Tunnel with Encryption")
    print("=" * 50)

    import secrets

    # Generate session keys
    key = secrets.token_bytes(32)
    encrypt_key = key
    decrypt_key = key  # Same key for loopback

    # Create UDP sockets
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind(('127.0.0.1', 0))
    client_addr = client_sock.getsockname()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('127.0.0.1', 0))
    server_addr = server_sock.getsockname()

    print(f"  Client listening on {client_addr}")
    print(f"  Server listening on {server_addr}")

    # Create crypto
    crypto = CryptoManager(key)

    received = []
    stop_event = threading.Event()

    def server_thread():
        """Server receives encrypted packets and echoes them back."""
        server_sock.settimeout(5.0)
        while not stop_event.is_set():
            try:
                data, addr = server_sock.recvfrom(65535)
                # Decrypt
                try:
                    decrypted = crypto.decrypt(data)
                    # Re-encrypt and send back
                    encrypted = crypto.encrypt(decrypted)
                    server_sock.sendto(encrypted, addr)
                except Exception as e:
                    print(f"  Server error: {e}")
            except socket.timeout:
                pass
            except Exception as e:
                if not stop_event.is_set():
                    print(f"  Server error: {e}")

    # Start server
    server = threading.Thread(target=server_thread, daemon=True)
    server.start()

    # Send test packets
    test_packets = [
        b"Hello, VPN Server!",
        b"Testing 123",
        b"A" * 500,
    ]

    client_sock.settimeout(5.0)

    for packet in test_packets:
        # Encrypt and send
        encrypted = crypto.encrypt(packet)
        client_sock.sendto(encrypted, server_addr)

        # Receive and decrypt
        data, addr = client_sock.recvfrom(65535)
        decrypted = crypto.decrypt(data)

        assert decrypted == packet, f"Packet mismatch: {decrypted} != {packet}"
        print(f"  [OK] Sent {len(packet)} bytes -> received back correctly")

    stop_event.set()
    client_sock.close()
    server_sock.close()
    server.join(timeout=1)

    print("\nUDP tunnel test PASSED!")
    return True


def test_handshake():
    """Test full handshake protocol."""
    print("\n" + "=" * 50)
    print("TEST 4: TCP Handshake Protocol")
    print("=" * 50)

    stop_event = threading.Event()
    handshake_result = [None]
    server_key = KeyExchange()

    def run_server():
        """Server handles handshake."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', 55521))
        server_sock.listen(1)
        server_sock.settimeout(10.0)

        try:
            conn, addr = server_sock.accept()
            print(f"  Server: Connection from {addr}")

            # Receive ClientHello
            header = conn.recv(5)
            msg_type = header[0]
            length = int.from_bytes(header[1:5], 'big')
            data = conn.recv(length)

            print(f"  Server: Received ClientHello (type={msg_type}, {len(data)} bytes)")

            # Send ServerHello
            from client.handshake import ServerHello
            server_hello = ServerHello(
                public_key=server_key.get_public_key_bytes(),
                nonce=secrets.token_bytes(32)
            )

            msg_data = server_hello.serialize()
            header = bytes([2]) + len(msg_data).to_bytes(4, 'big')
            conn.sendall(header + msg_data)
            print(f"  Server: Sent ServerHello")

            # Receive ClientAck
            header = b''
            while len(header) < 5:
                header += conn.recv(5 - len(header))
            msg_type = header[0]
            length = int.from_bytes(header[1:5], 'big')
            data = conn.recv(length)
            print(f"  Server: Received ClientAck ({len(data)} bytes)")

            # Send UDP port
            port_data = (51200).to_bytes(2, 'big')
            header = bytes([3]) + len(port_data).to_bytes(4, 'big')
            conn.sendall(header + port_data)
            print(f"  Server: Sent UDP port info")

            conn.close()
        except Exception as e:
            print(f"  Server error: {e}")
        finally:
            server_sock.close()

    # Start server
    server = threading.Thread(target=run_server, daemon=True)
    server.start()

    time.sleep(0.5)

    # Run client
    try:
        client = HandshakeClient(server_pubkey=server_key.get_public_key_bytes())
        result = client.perform_handshake('127.0.0.1', 55521, timeout=10.0)

        print(f"\n  Client: Handshake SUCCESS!")
        print(f"  UDP port: {result.udp_port}")
        print(f"  Session keys derived: Yes")

        handshake_result[0] = result
    except Exception as e:
        print(f"\n  Client: Handshake FAILED: {e}")
        import traceback
        traceback.print_exc()

    stop_event.set()
    server.join(timeout=2)

    if handshake_result[0]:
        print("\nHandshake test PASSED!")
        return True
    else:
        print("\nHandshake test FAILED!")
        return False


def test_real_handshake_server():
    """Test the real HandshakeServer/HandshakeClient integration."""
    print("\n" + "=" * 50)
    print("TEST 5: Real HandshakeServer Integration")
    print("=" * 50)

    server_private, server_public = generate_keypair()
    server_keys = [None]
    server_error = [None]

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('127.0.0.1', 0))
    server_sock.listen(1)
    server_sock.settimeout(10.0)
    handshake_port = server_sock.getsockname()[1]

    def run_server():
        server_impl = HandshakeServer(private_key=server_private)
        try:
            conn, addr = server_sock.accept()
            print(f"  Real server: Connection from {addr}")
            server_keys[0] = server_impl.handle_handshake(conn, 51200)
            conn.close()
        except Exception as e:
            server_error[0] = e
        finally:
            server_sock.close()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    time.sleep(0.2)

    try:
        client = HandshakeClient(server_pubkey=server_public)
        result = client.perform_handshake('127.0.0.1', handshake_port, timeout=10.0)
    except Exception as e:
        print(f"  Real handshake failed: {e}")
        return False

    thread.join(timeout=2)

    if server_error[0] is not None:
        print(f"  Server thread error: {server_error[0]}")
        return False

    if server_keys[0] is None:
        print("  Server did not derive session keys")
        return False

    assert result.session_keys.encrypt_key == server_keys[0].decrypt_key, "Client/server key mismatch"
    assert result.session_keys.decrypt_key == server_keys[0].encrypt_key, "Client/server key mismatch"

    print("  [OK] Real handshake path produced matching keys")
    print("\nReal handshake integration test PASSED!")
    return True


def test_tunnel_key_direction_mapping():
    """Verify tunnel uses server-direction keys without double swap."""
    print("\n" + "=" * 50)
    print("TEST 6: Tunnel Key Direction Mapping")
    print("=" * 50)

    client_kx = KeyExchange()
    server_kx = KeyExchange()
    nonce = secrets.token_bytes(32)

    client_keys = client_kx.derive_session_keys(server_kx.get_public_key_bytes(), nonce)
    server_keys = server_kx.derive_session_keys(client_kx.get_public_key_bytes(), nonce)

    tunnel_server = TunnelServer()
    tunnel_server.set_session_keys(server_keys)

    # Client -> Server direction must decrypt with server decryptor.
    c2s_msg = b"client-to-server-packet"
    c2s_cipher = CryptoManager(client_keys.encrypt_key).encrypt(c2s_msg)
    c2s_plain = tunnel_server._decryptor.decrypt(c2s_cipher)
    assert c2s_plain == c2s_msg, "Server decryptor key mapping is incorrect"

    # Server -> Client direction must decrypt with client decrypt key.
    s2c_msg = b"server-to-client-packet"
    s2c_cipher = tunnel_server._encryptor.encrypt(s2c_msg)
    s2c_plain = CryptoManager(client_keys.decrypt_key).decrypt(s2c_cipher)
    assert s2c_plain == s2c_msg, "Server encryptor key mapping is incorrect"

    print("  [OK] Tunnel key direction mapping is correct")
    print("\nTunnel key mapping test PASSED!")
    return True


def main():
    print("=" * 50)
    print("VPN Component Tests (No TUN Required)")
    print("=" * 50)

    results = []

    results.append(("Encryption", test_encryption()))
    results.append(("Key Exchange", test_key_exchange()))
    results.append(("UDP Tunnel", test_udp_tunnel()))
    results.append(("Handshake", test_handshake()))
    results.append(("Real Handshake", test_real_handshake_server()))
    results.append(("Tunnel Key Mapping", test_tunnel_key_direction_mapping()))

    print("\n" + "=" * 50)
    print("RESULTS")
    print("=" * 50)

    all_passed = True
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print("=" * 50)
    if all_passed:
        print("\nAll tests PASSED!")
        print("\nThe VPN core (encryption, key exchange, handshake, UDP)")
        print("is working correctly. The only missing piece is the TUN")
        print("interface, which requires the Wintun driver to work.")
        return 0
    else:
        print("\nSome tests FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
