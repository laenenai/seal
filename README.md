# seal

[![ci](https://github.com/laenenai/seal/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/seal/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/seal.svg)](https://pkg.go.dev/github.com/laenenai/seal)

Encrypts and decrypts opaque bytes under a caller-supplied data key, in a
versioned, vector-pinned format whose ciphertext is bound to the one place it
belongs — so a value cannot be spliced or relocated and still decrypt.

> **Status: design only.** This repository currently contains the charter and
> the boundary. There is no implementation yet, and no release. The streaming
> format is an extraction of a working implementation with a committed format
> specification and test vectors, scheduled after its current consumer's
> milestone.

## What it does

Two shapes, one format family, one key path:

- **A framed stream** for blobs — `io.Writer` / `io.Reader`, with **ranged
  reads that decrypt only the frames they need**. Detects truncation of the
  final frame, reordering, and any bit flip including in the header.
- **A compact record** for small values, because a 25-byte header plus a
  16-byte tag per frame is 0.004% overhead on a megabyte and over 200% on a
  twenty-byte value.

Format is chosen by whether ranged reads are needed; API shape by where the
bytes are. Every one-shot entry point carries an explicit size ceiling,
checked **before allocation** and failing closed on an unknown length.

## The property that matters

The AEAD's additional authenticated data binds ciphertext to its address. A
value moved from one row to another — by a bug, or by anyone with database
write access — becomes a **decryption failure rather than a silent wrong
answer**. Confidentiality without integrity of placement is not enough.

## What it does not do

Key management, wrapping or custody; what the bytes mean; the data key's
lifecycle; policy of any kind.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, the properties preserved verbatim from the extracted format, and the five rules on the size ceiling
- [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
