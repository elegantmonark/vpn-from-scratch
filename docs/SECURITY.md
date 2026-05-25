# Security Notes

This is an educational VPN implementation. It demonstrates important VPN design pieces, but it is not a production security product.

## Implemented

- X25519 key exchange.
- HKDF session-key derivation.
- AES-256-GCM authenticated encryption.
- Random nonces for packet encryption.
- Timestamp checking in the handshake.
- Public-key pinning for server authentication.
- Explicit opt-in insecure mode for local testing.

## Not Production-Hardened

- No external audit.
- No formal UDP replay window.
- No production-grade kill switch.
- No mature route-leak protection.
- No key rotation schedule.
- No denial-of-service hardening.
- Limited operational logging and diagnostics.
- Platform-specific routing/NAT behaviour is still experimental.

## Private Key Handling

The server private key is stored locally as:

```text
config/server.key
```

This file is ignored by git and must never be committed.

If this project is cloned for development, generate a fresh local keypair instead of reusing someone else's key.

## Recommended Real-World Alternatives

Use a mature and audited VPN implementation for real security needs:

- WireGuard
- OpenVPN
- IPsec implementations maintained by operating-system vendors

This repository should be treated as an educational systems/security project.
