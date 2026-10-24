# seal

[![ci](https://github.com/laenenai/seal/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/seal/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/seal.svg)](https://pkg.go.dev/github.com/laenenai/seal)

Encrypts and decrypts opaque bytes under a caller-supplied data key, in a
versioned, vector-pinned format whose ciphertext is bound to the one place it
belongs — so a value cannot be spliced or relocated and still decrypt.

> **Status: both formats are implemented; there is no release and no external
> review.**
>
> **In, and tested:** the framed stream (format version 1), extracted from
> `cas/internal/crypto` — all 24 of its property tests ported under their own
> names, with committed vectors that pin the format against future drift; the
> compact record (format version 2), new, with its own committed vectors; both
> API shapes over both formats; the five size-ceiling rules, each with a named
> subtest; two ports behind conformance suites in `sealtest`; the rendering
> discipline on every value the module hands back.
>
> **Not wire-compatible with `cas/internal/crypto`, deliberately.** CAS's magic
> and HKDF info string were `CASF1`; both are renamed to `SEAL1` here, which
> changes the frame key and every tag. Ciphertext CAS wrote does not decrypt
> under `seal` and there is no compatibility shim. Nothing had ever been
> persisted — CAS is unreleased, untagged, with no deployment and no stored
> blobs — so there was no data to be compatible with, and no reason to carry
> another module's spelling forever. CAS keeps its own copy until it swaps, at
> which point it still has nothing stored.
>
> **Deliberately out of scope in this pass**, each noted here rather than left
> to be discovered:
>
> - **No release.** No tag. A consumer pins a commit.
> - **No external security review.** The framed format carries CAS's review
>   history; **format version 2 is new code in a module whose whole subject is
>   cryptographic construction, and nobody outside this work has looked at
>   it.** Its construction is documented in [`docs/format.md`](docs/format.md),
>   including the arithmetic behind its nonce claim, specifically so that
>   review is possible without reading the implementation first.
> - **No consumer has run the suites yet.** Both ports pass against this
>   module's own implementations. CAS has a working framed implementation, and
>   running `sealtest.RunStreamSealerSuite` against it is what will make the
>   swap a verified substitution rather than a rewrite; that has not happened.
> - **No key management, of any kind.** A DEK arrives from
>   [`keyring`](https://github.com/laenenai/keyring) and this module never
>   generates, wraps, stores, rotates or destroys one.

## The property that matters

The AEAD's additional authenticated data binds ciphertext to its address. A
value moved from one row to another — by a bug, or by anyone with database
write access — becomes a **decryption failure rather than a silent wrong
answer**.

An encrypted `salary` relocated onto a colleague's row decrypts perfectly and
answers the wrong question. No amount of key hygiene prevents that, because
nothing in the ciphertext says where it belonged. This is leak channel #17 in
the `kgs` design, and it is why this is a module rather than a helper:
confidentiality without integrity of placement is not enough.

## Two shapes, one format family, one version space

**Format** is chosen by whether ranged reads are needed. **API shape** is
chosen by where the bytes are.

| | framed stream (v1) | compact record (v2) |
|---|---|---|
| for | blobs, anything read by range | a whole small value |
| binds to | `(tenant, object)` | an ordered list of components, e.g. `(graph, fact id, attribute)` |
| overhead | 25-byte header + 16 bytes per frame | 33 bytes, flat |
| ranged reads | yes — decrypts only the frames a range overlaps | no |
| streaming | `io.Writer` / `io.ReadCloser` / `io.ReaderAt` | offered, and it buffers the whole value |
| one-shot | `EncryptObject` / `DecryptObject`, bounded | `EncryptRecord` / `DecryptRecord`, bounded |

Both versions live in **one numbered space**, and each version is bound into
its own AAD, so a ciphertext written under one can never be opened as another.
Every identifier says the same number: the framed stream's magic is `SEAL1` and
its HKDF info `"SEAL1 frame key"`; the compact record's wire byte is `2` and its
HKDF info `"SEAL2 record key"`.

It detects truncation of the final frame, reordering, and any bit flip
**including in the header** — achieved by binding the whole 25-byte header into
every frame's AAD rather than giving the header a tag of its own. The
`frame_size` bounds check is a **separate** mechanism that authenticates
nothing and exists only to bound decoder resource use; the format document
keeps the two apart, because that is the distinction a rewrite loses.

### What the compact record actually saves

| plaintext | framed stream | compact record |
|---|---|---|
| 20 B | 61 B (205% overhead) | 53 B (165% overhead) |
| 1 KiB | 1065 B (4.0%) | 1057 B (3.2%) |
| 1 MiB | 1048617 B (0.004%) | 1048609 B (0.003%) |

Eight bytes, not an order of magnitude — the figure is in the table rather than
in an adjective. What makes the compact record the right tool for tens of
millions of short values is that it costs **one AEAD operation and no framing
state**, and that it binds to an arbitrary address rather than a
`(tenant, object)` pair.

## Nonce management at scale, with the arithmetic

One DEK encrypting ten million small records is inside the territory where
random 96-bit nonces need an argument. So both formats derive a per-unit key
from a per-unit 128-bit random salt — per stream for v1, per record for v2 —
which is what `keyring`'s local adapter already does for the analogous problem.
A `(key, nonce)` pair then repeats only on a salt collision:

| construction | units per DEK at a 2⁻³² collision risk |
|---|---|
| one key, random 96-bit nonce | ≈ 2³²·⁵ ≈ 6.1 × 10⁹ |
| per-unit key from a 128-bit salt | ≈ 2⁴⁸·⁵ ≈ 4.0 × 10¹⁴ |

A factor of 65,536. **Not "uncapped"** — the honest claim is the comparison.
The working is in [`docs/format.md`](docs/format.md), along with why deriving
the salt from the address (which would have removed all 16 bytes from the wire)
was rejected.

## The size ceilings are security controls

Every one-shot entry point carries a `Limits`; the streaming framed reader
carries a total plaintext ceiling. Five rules:

1. **Two separate limits.** A plaintext ceiling bounds what a caller hands us;
   a **ciphertext** ceiling bounds decrypt, and that is the one that matters,
   because an attacker controls the ciphertext's length.
2. **Checked before allocation**, from a declared or derivable length — never
   by reading and discovering. Kept distinct from `frame_size`'s bound.
3. **Fail closed on an unknown length.** `ErrUnknownLength` when a ceiling is
   configured and the length cannot be established up front.
4. **A typed error naming the limit** — `*LimitError`, matching
   `ErrLimitExceeded` — and **no result at all** beside it. A partial plaintext
   from a bounded decrypt is worse than a refusal.
5. **Streaming is not exempt.** Streaming bounds *our* memory to one frame; it
   does not bound the caller's.

A zero `Limits` field means **this entry point's default** (1 MiB), never
"unbounded"; `Unlimited` must be written out, because the zero value is what a
caller gets when they forget.

## Using it

```go
dek, err := km.UnwrapDEK(ctx, wrapped) // keyring
if err != nil {
    return err
}
defer dek.Destroy()

addr, err := seal.NewRecordAddress(graphID, factID, "salary")
if err != nil {
    return err
}
record, err := seal.EncryptRecord(dek, addr, []byte(value), seal.Limits{})
```

## What it does not do

Key management, wrapping or custody ([`keyring`](https://github.com/laenenai/keyring),
and [`escrow`](https://github.com/laenenai/escrow) for keyring's KEKs); what
the bytes mean; the data key's lifecycle; policy of any kind.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, the properties preserved verbatim from the extracted format, the five ceiling rules, and the adoption state
- [`docs/format.md`](docs/format.md) — the committed wire format for both versions, the version registry, the naming decision, the nonce arithmetic, and the test-vector rule
- [`SECURITY.md`](SECURITY.md)
- [`CONVENTIONS.md`](CONVENTIONS.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## Running the tests

    mise run test       # the inner loop
    mise run test-all   # everything, with the race detector
    mise run check      # the gate: fmt-check, lint, build, test-all

There are no containers and no database: this module performs no I/O. `-short`
is honoured as a runtime decision in the two subtests that sweep a property
rather than sample it, never behind a build tag.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
