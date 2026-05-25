# Architecture

This project is split into four main layers:

```text
UI / command entrypoint
        |
        v
Handshake and session setup
        |
        v
Encrypted UDP tunnel
        |
        v
TUN/Wintun virtual network interface
```

## Client

The client is responsible for:

- Loading server configuration.
- Performing the TCP handshake.
- Deriving session keys.
- Opening the local TUN/Wintun interface.
- Encrypting outbound packets.
- Decrypting inbound packets.
- Updating UI status and traffic counters.

Relevant modules:

- `client/crypto.py`
- `client/handshake.py`
- `client/tunnel.py`
- `client/wintun.py`
- `ui/main.py`

## Server

The server is responsible for:

- Loading or generating the server keypair.
- Accepting handshake requests.
- Authenticating/deriving session keys.
- Receiving encrypted UDP packets.
- Decrypting and forwarding packets to the virtual interface.
- Handling NAT/routing hooks.

Relevant modules:

- `server/main.py`
- `server/nat.py`
- `client/handshake.py`
- `client/tunnel.py`

## Packet Flow

```text
Client application packet
        |
        v
Client virtual interface
        |
        v
AES-GCM encrypt
        |
        v
UDP send
        |
        v
Server UDP receive
        |
        v
AES-GCM decrypt
        |
        v
Server virtual interface / routing
```

## Handshake

The handshake uses TCP for reliable setup before switching to UDP packet transport.

```text
1. Client sends protocol version, timestamp, and X25519 public key.
2. Server replies with its X25519 public key and HKDF salt.
3. Client verifies the pinned server key unless insecure local mode is enabled.
4. Client sends an encrypted confirmation message.
5. Both sides use derived session keys for UDP packet transport.
```

## Configuration

The repository includes example config files only:

- `config/server.example.json`
- `config/servers.example.json`

Runtime configs and private keys are intentionally ignored by git:

- `config/server.json`
- `config/servers.json`
- `config/server.key`

