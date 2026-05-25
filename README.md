# VPN From Scratch

An educational VPN prototype implemented in Python using virtual network interfaces, encrypted UDP tunnelling, AES-GCM packet encryption, and an X25519-based handshake.

> **Status:** learning/research prototype, not a production VPN.

## Abstract

This project explores how a VPN works internally by implementing the main components directly rather than wrapping an existing VPN framework. The prototype creates virtual network interfaces, performs an authenticated key exchange, derives session keys, encrypts packets, and transports them over UDP between a client and server.

The current implementation is designed for experimentation and systems learning. It demonstrates the structure of an encrypted tunnel, but it does not yet provide the operational hardening expected from production VPN software.

## 1. Project Goal

The goal is to build a minimal VPN from first principles and make each layer understandable:

- Virtual network interface creation using TUN/Wintun.
- Session setup using a TCP handshake.
- X25519 key agreement with HKDF-derived keys.
- AES-GCM authenticated packet encryption.
- UDP transport for encrypted tunnel packets.
- A simple desktop client UI for server selection and connection state.
- Server public-key pinning for identity verification.

The project is intentionally educational. It is useful for understanding VPN architecture, packet tunnelling, virtual interfaces, routing, and applied cryptography.

## 2. Current Capability

| Component | Current state |
| --- | --- |
| Windows client | Uses Wintun-oriented interface code, performs handshake, encrypts packets, sends UDP tunnel packets, and provides a Tkinter UI. |
| Linux/server side | Uses TUN-oriented interface concepts, receives encrypted UDP packets, decrypts them, and forwards them into the server-side tunnel path. |
| Handshake | TCP handshake with protocol version, timestamp, X25519 public keys, HKDF salt, and encrypted client confirmation. |
| Encryption | AES-256-GCM with random nonces for authenticated packet encryption. |
| Server authentication | Public-key pinning by default, with explicit insecure mode only for local testing. |
| Configuration | JSON-based server and client configuration using public example files. |
| Testing | Includes local unit/loopback style scripts for crypto, handshake, and tunnel flow checks. |
| Not complete | Production NAT/routing, kill switch guarantees, replay-window hardening, installer flow, and external security review. |

## 3. System Architecture

```text
Application traffic
        |
        v
Client TUN / Wintun interface
        |
        v
Packet encryption with AES-GCM
        |
        v
Encrypted UDP tunnel
        |
        v
Server decrypts packet
        |
        v
Server TUN / Wintun interface
        |
        v
NAT / routing layer
        |
        v
Network / internet
```

The client captures packets from a virtual interface, encrypts them, and sends them to the server over UDP. The server decrypts those packets and forwards them through its own virtual interface and routing layer.

## 4. Handshake Design

The handshake uses TCP before switching to UDP tunnel transport.

```text
1. ClientHello
   - protocol version
   - Unix timestamp
   - client X25519 public key

2. ServerHello
   - server X25519 public key
   - HKDF salt / nonce

3. ClientAck
   - encrypted confirmation message

4. UDP tunnel starts
   - both sides use derived session keys
```

The timestamp check helps reject stale or future handshakes. Server public-key pinning is used to avoid silently accepting an unknown server identity.

## 5. Cryptographic Model

The project uses:

- **X25519** for key agreement.
- **HKDF** for deriving session keys from the shared secret.
- **AES-256-GCM** for authenticated encryption.
- **Random 96-bit nonces** for encrypted packet messages.
- **Directional session keys** for client-to-server and server-to-client traffic.

This is a useful educational cryptographic structure, but it should not be treated as equivalent to a reviewed production VPN protocol.

## 6. Repository Structure

```text
vpn-project/
|-- client/
|   |-- crypto.py
|   |-- handshake.py
|   |-- tunnel.py
|   `-- wintun.py
|-- server/
|   |-- main.py
|   `-- nat.py
|-- ui/
|   `-- main.py
|-- config/
|   |-- server.example.json
|   `-- servers.example.json
|-- docs/
|   |-- ARCHITECTURE.md
|   `-- SECURITY.md
|-- wintun/
|   `-- README.md
|-- vpn.py
|-- test_tun.py
|-- test_vpn_loopback.py
`-- requirements.txt
```

## 7. Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Download Wintun for Windows from:

```text
https://www.wintun.net/
```

Place the local DLL at:

```text
wintun/wintun.dll
```

The DLL is not committed to this repository.

## 8. Configuration

Copy the example files before local use:

```bash
cp config/server.example.json config/server.json
cp config/servers.example.json config/servers.json
```

On Windows PowerShell:

```powershell
Copy-Item config\server.example.json config\server.json
Copy-Item config\servers.example.json config\servers.json
```

Private server keys are stored locally at:

```text
config/server.key
```

This file is ignored by git and must never be published.

## 9. Running The Prototype

Run the server:

```bash
python vpn.py server
```

Run the client UI:

```bash
python vpn.py client
```

Run built-in tests:

```bash
python vpn.py test
```

Run the loopback integration script:

```bash
python test_vpn_loopback.py
```

Administrative privileges may be required for virtual interface creation and route configuration.

## 10. Testing And Validation

The current project includes tests for:

- AES-GCM encryption/decryption.
- X25519 key agreement.
- Handshake behaviour.
- Tunnel packet flow.
- Local loopback behaviour.

Syntax validation can be run with:

```bash
python -m compileall .
```

## 11. Limitations

This project is not production-ready. Known limitations include:

- No external security audit.
- No formal UDP replay-protection window.
- No mature kill switch.
- NAT/routing behaviour is still platform-dependent.
- No installer or service-management layer.
- Limited error handling for hostile network conditions.
- No mature multi-client session management.
- No performance optimisation for high-throughput traffic.

## 12. Future Work

Possible development directions:

- Harden the UDP transport layer with replay windows.
- Improve route setup and teardown across Windows and Linux.
- Add a robust kill switch.
- Add structured logging and diagnostics.
- Add integration tests that do not require privileged interfaces.
- Improve multi-client server handling.
- Add diagrams/screenshots of the UI and packet flow.
- Package the project as a clean educational lab.

## 13. Security Disclaimer

This project is for educational use only. Do not use it as a real privacy, security, or anonymity product. For real-world VPN use, choose a mature and reviewed implementation such as WireGuard, OpenVPN, or an operating-system maintained IPsec stack.

## License

MIT
