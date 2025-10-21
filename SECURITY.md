# Threat Model
- Goal: protect data at rest and during transit (file sharing).
- Attacker: can read/modify ciphertext but has no live access to your machine memory.
- In-scope: brute-force resistance (Argon2id), tamper detection (AEAD tag), safe key/nonce handling.
- Out-of-scope: keyloggers, supply-chain compromise, side-channels, coercion.
- Keys: per-file random content key; envelope-encrypted for recipients (X25519 sealed boxes).
