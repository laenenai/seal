# Examples

Runnable examples for the two SEAL formats and the conformance suites. They are
part of the module, so `go build ./...`, `go test ./...`, and `mise run check`
keep them compiling and current.

Run them from the repository root:

```bash
go run ./examples/records
go run ./examples/streaming
go run ./examples/range
go test ./examples/conformance
```

The examples use `keyring.NewDEK()` to stay self-contained. In production the
DEK comes from your key manager; see [`keyring`](https://github.com/laenenai/keyring).

## Choose a format by read pattern

| Need | Use | Entry points |
|---|---|---|
| One small whole value (a fact literal, a short JSON blob) | Compact record, format version 2 | `EncryptRecord` / `DecryptRecord` |
| A blob read sequentially or as a whole | Framed stream, format version 1 | `NewEncryptWriter` / `NewDecryptReader`, or `EncryptObject` / `DecryptObject` |
| Ranged reads without decrypting the whole object | Framed stream, format version 1 | `NewDecryptRangeReader` |
| A caller already holding `io.Reader`/`io.Writer` | Either format's streaming shapes | `NewRecordWriter` / `NewRecordReader`, or the framed writer/reader |

Do not choose the compact record just because it is eight bytes smaller on a
small value. The real differences are that it has no framing and no ranged
reads, and that it binds to an arbitrary address rather than a
`(tenant, object)` pair.

## What each example shows

### [`records`](records/main.go)

A compact record for one small value, bound to `(graph, fact, attribute)`. The
example decrypts it, then tries the same ciphertext at a different address and
shows that it fails with `seal.ErrCorrupt`. That is the point of the AAD
binding: relocation is a decryption failure, not a silent wrong answer.

### [`streaming`](streaming/main.go)

A framed stream written in chunks and read back through
`NewDecryptReader`. It demonstrates the `Close` contract:

- The writer's `Close` seals the final frame. A writer that is never closed
  never produces a complete stream.
- The reader's `Close` authenticates any frames the caller did not read. Check
  its error even after a successful `Read`.
- `Close` on an abandoned reader can cost as much as decrypting the rest of the
  object. Do not call it synchronously on a request goroutine that a client can
  abandon if that cost matters.

### [`range`](range/main.go)

A multi-frame object and a range that crosses a frame boundary. The range
reader decrypts only the frames the range overlaps and holds at most one frame
of plaintext.

The `size` argument must be the authoritative stored ciphertext size from your
metadata row, not a live `Stat` of the object store. The range reader derives
every check from `size`; a caller that lets the storage layer report a
truncated size can make a prefix range authenticate while the object's tail is
missing. Only a full sequential `NewDecryptReader` pass authenticates an object
end to end.

### [`conformance`](conformance/conformance_test.go)

Shows how a consumer runs `sealtest.RunRecordSealerSuite` and
`sealtest.RunStreamSealerSuite` against an implementation. Swap the factory's
return value for your adapter. The suites are the authoritative description of
the port contract; the interfaces alone are not.

## Best practices

### Keys and lifecycle

- Keep key management outside `seal`. Generate, wrap, store, rotate, and destroy
  DEKs with `keyring` (or another key manager). `seal` never does any of it.
- Destroy the DEK when the operation is done: `defer dek.Destroy()`.
- Never reuse a DEK for unrelated data just because it is convenient. The
  construction tolerates reuse better than a bare nonce, but the operational
  and blast-radius argument for per-object/per-record keys still applies.
- Do not log, render, or serialize a DEK, a derived key, or plaintext. `seal`'s
  returned types redact themselves, but derived key schedules and plaintext
  buffers are not zeroized by the Go runtime; treat process memory as sensitive.

### Addresses

- Use a stable, unique address component for the value's whole lifetime. For a
  framed object, `(tenant, object)` must identify exactly one object. For a
  compact record, the ordered components must identify exactly one place.
- Do not use a mutable display name, a current storage path, a truncated
  content address, or a value that can collide with another object of the same
  tenant. The uniqueness premise is yours; `seal` cannot enforce it.
- Present the exact same bytes at decrypt time. `seal` does not parse or
  canonicalize the components.
- Store the format/version alongside the ciphertext. A compact record is not
  self-identifying the way a framed stream is by its `SEAL1` magic.

### Limits and errors

- A zero `Limits` field means the entry point's default (1 MiB for
  `MaxPlaintext`; a derived ciphertext ceiling). It never means "unbounded."
  Write `seal.Unlimited` explicitly if you mean it.
- Set `MaxCiphertext` directly when reading ciphertext from a source you do not
  control. It bounds what an attacker can make you allocate or read.
- Use `errors.Is(err, seal.ErrCorrupt)` for authentication/placement failures,
  `errors.As(err, &limitErr)` for a specific ceiling, and `errors.Is(err,
  seal.ErrRange)` for a bad byte range. `ErrCorrupt` deliberately does not say
  which check failed.
- A streaming reader can return an authenticated prefix before a limit error.
  Do not treat a partial read as the complete object; the one-shot entry points
  return no plaintext on failure, but streaming cannot un-hand bytes.
- Always check `Close` on a decrypt reader, even after a successful `Read`.

### Ranged reads

- Pass the authoritative ciphertext `size` from trusted metadata, not a
  backend `Stat` at read time.
- A ranged read does not authenticate the whole object. If you need
  whole-object integrity, use a full sequential `NewDecryptReader` pass or
  keep a trusted total-length commitment in metadata.
- A ranged read does not have a separate plaintext ceiling: `length` is the
  bound the caller states. Do not pass an attacker-controlled `length` larger
  than you are prepared to read.

### Compatibility and releases

`seal` is pre-1.0. Public API changes are checked with
`mise run api-diff` against the last root tag, and release validation uses
`gorelease` on a clean tag. Read [`../CHANGELOG.md`](../CHANGELOG.md) and
[`../UPGRADING.md`](../UPGRADING.md) before upgrading. Set
`API_DIFF_STRICT=1` after 1.0.

## Further reading

- [`../README.md`](../README.md) — what the module does and does not do
- [`../docs/format.md`](../docs/format.md) — wire format, AAD, nonces, vectors
- [`../SECURITY.md`](../SECURITY.md) — disclosure and security scope
- [`../CHARTER.md`](../CHARTER.md) — the module boundary
