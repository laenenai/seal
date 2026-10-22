# seal

Encrypts and decrypts opaque bytes under a caller-supplied DEK, in a versioned,
documented, vector-pinned format whose ciphertext is bound to the one place it
belongs — so a value cannot be spliced or relocated and still decrypt.

Two shapes: a **framed stream** (CASF1) with ranged reads, for blobs; and a
**compact record** for small values, where a 41-byte envelope on a 20-byte
value is not acceptable.

**Not in scope:** key management, wrapping or custody (`keyring`, `escrow`),
what the bytes mean, the DEK's lifecycle, policy.

See [CHARTER.md](CHARTER.md).
