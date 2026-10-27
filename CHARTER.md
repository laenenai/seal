# Charter: `seal`

**It does this one thing:** Encrypt and decrypt **opaque bytes** under a
caller-supplied DEK, in a versioned, documented, test-vector-pinned format
whose ciphertext is bound to the one place it belongs.

**It must not contain:** Key management, wrapping or custody (`keyring`,
`escrow`). Any knowledge of what the bytes mean. The DEK's lifecycle — who
generated it, where its wrapped form is stored, when it is destroyed. Policy
of any kind.

## Why this is a module and not a helper in `keyring`

It passes the test that justifies one: a consumer plausibly wants `keyring`
without `seal` — anything that only wraps keys, or that delegates encryption
to a transit engine entirely — but nobody wants `seal` without a DEK from
somewhere. One-directional dependency (`seal` → `keyring`, for the zeroizable
`DEK` type only), two genuinely different jobs.

The alternative was helpers inside `keyring`, rejected because `keyring`'s
charter says it must not contain what is being encrypted, and because an
envelope format is a **stored artifact with its own compatibility surface**.
Ciphertext written today must decrypt in five years; that deserves its own
versioned repository, its own format document and its own committed vectors,
not a subdirectory of a key manager.

## It is an extraction, not a design

`cas/internal/crypto` already is this, and it is good: **CASF1**, a framed
streaming AEAD with a 298-line committed format specification pinned by
`testdata/vectors.json`, where a test decrypts the committed ciphertext so the
document and the code cannot drift silently. 656 lines of implementation, 771
of tests.

Properties to preserve verbatim, because each one is a bug someone already
found:

- truncation detection — a dropped final frame;
- reorder detection — two frames swapped, or one dropped from the middle;
- bit-flip detection **anywhere, including the header**, achieved by binding
  the whole 25-byte header into every frame's AAD rather than giving the header
  a tag of its own;
- a `frame_size` bounds check that exists purely to bound decoder resource use
  and authenticates nothing — the format document is explicit that these are
  two separate mechanisms, and that is the sort of distinction that gets lost
  in a rewrite;
- ranged reads that decrypt only the frames they need;
- **AAD binding ciphertext to exactly one object of exactly one tenant**, so a
  frame cannot be spliced or replayed from one object into another, even within
  the same tenant.

Per the project's extraction rule: take the most advanced consumer's working
code, never design fresh.

**Done, 2026-10-24.** The framed format is `internal/framed`. Every property
above is preserved and all 24 of CAS's tests are ported under their own names,
because a renamed test is a test nobody can trace back to its bug.
`testdata/vectors.json` keeps CAS's fixture inputs — the same DEKs, salts, frame
sizes, tenant and content addresses — so what the extraction changed is visible,
and `TestVectors_MatchCommittedTestdata` decrypts the committed ciphertext
directly, which is what stops `docs/format.md` and the code drifting silently.
CAS keeps its copy until it swaps, and `sealtest.RunStreamSealerSuite` is what
it can run against that copy in the meantime.

The earlier sequencing note here — "after CAS's ~2026-11-05 alpha" — is stale
and is removed rather than left to be believed: the owner reordered to implement
every module before returning to CAS, which made `seal` the thing blocking CAS's
step 4 rather than something waiting on it.

### What the format family is called, and what it is not compatible with

The family is **SEAL**, with one numbered version space across both shapes:
version 1 is the framed stream, version 2 the compact record, and the next
change to either takes the next number rather than starting a second counter.
Every identifier says that number — the framed magic is `SEAL1` and its HKDF
info `"SEAL1 frame key"`; the compact record's wire byte is `2` and its HKDF
info `"SEAL2 record key"` — so there is nothing to keep in step.

**The wire format is deliberately not compatible with `cas/internal/crypto`.**
CAS's magic and info string were `CASF1`; both are renamed, which changes the
frame key and every tag, so ciphertext CAS wrote does not decrypt here. There is
no second accepted magic and no version shim. The rename cost nothing because
**nothing has ever been persisted** — CAS is unreleased and untagged, with no
deployment and no stored blobs — so there was no data to be compatible with, and
carrying another module's spelling forever for bytes that do not exist is debt
taken on for no return. CAS keeps its own copy until it swaps, at which point it
still has nothing stored.

The committed vectors were regenerated once, for that rename, and must not be
regenerated again casually. What they protect is **future** drift between
`docs/format.md` and the code; that survives one deliberate regeneration and is
lost only to a careless one.

There is no shared *stored* prefix across the two shapes: a framed stream spends
five bytes on its magic because it has a header and a blob can afford it, and a
compact record spends one, because four or five more would be a tenth of its
whole overhead for a self-description the caller already has from the column it
read. What a shared prefix would have bought is bought instead by binding each
version number into its own AAD, which costs nothing on the wire because AAD is
authenticated rather than stored.

## The shape the framed format does not have

**A compact record for small values.** The framed format's 25-byte header plus a
16-byte tag per frame is 0.004% overhead on a 1 MiB blob and **over 200% on a 20-byte
fact literal**. kgs encrypts per-attribute (its design §23.1), which means
potentially tens of millions of short values, so the framed format is the wrong
tool there.

So: two shapes, one format family, one key path, one version space — the same
reasoning that kept `meter`'s two metric shapes in one module. A compact record
has no framing, derives its nonce rather than storing it where the construction
allows, and binds its AAD to the value's address.

**That AAD binding is the point, not an optimisation.** Generalised from
the framed format's object binding, a kgs attribute value is bound to
`(graph, fact id, attribute)`. Without it an encrypted `salary` value can be
**relocated onto another row** — by a bug, or by anyone with database write
access — and will decrypt cleanly to the wrong answer. With it, relocation is
a decryption failure. This is recorded as leak channel #17 in the kgs design.

Nonce management at scale needs stating: a single DEK encrypting ten million
small records is well inside the territory where random 96-bit nonces must be
reasoned about rather than assumed safe. `keyring`'s local adapter already
solved the analogous problem by deriving a per-record key from a per-record
salt; the compact record should do the same, so the number of records one DEK
may seal is not capped by a birthday bound.

## Two API shapes, and the ceiling on the non-streaming one

Owner's requirement, 2026-10-23: streaming **and** non-streaming, the
non-streaming one with a maximum byte size.

Worth separating two axes that are easy to conflate:

- **Format** is chosen by whether ranged reads are needed: *framed* for
  blobs and anything read by range; *compact record* for a whole small value.
- **API shape** is chosen by where the bytes are: *streaming* (`io.Writer` /
  `io.Reader` / `io.ReaderAt` for ranges) or *one-shot* (`[]byte` in, `[]byte`
  out). Both shapes are offered over the compact format; the framed format is
  streaming-first, with a bounded one-shot convenience over it.

**Every one-shot entry point carries an explicit ceiling, and the ceiling is a
security control rather than a courtesy.** Five rules it must follow:

1. **Two separate limits, not one.** A plaintext ceiling on the encrypt side
   bounds what a caller may hand us. A *ciphertext* ceiling on the decrypt side
   is the one that matters, because an attacker controls the ciphertext's
   length.
2. **Checked before allocation**, from the declared or derivable length — never
   by reading and discovering. This is the allocation-bomb pattern, and the
   framed format already applies the same reasoning to `frame_size`, whose bounds exist
   "purely to bound decoder resource use" and authenticate nothing. Two
   mechanisms, kept distinct.
3. **Fail closed on an unknown length.** If a limit is configured and the input
   length cannot be established up front, the operation is refused. This is
   deliberately the same rule as CAS §9.2's `MaxContentLength` caveat, which
   "fails closed on an unknown length: a chunked upload with no declared size
   is refused when a limit caveat exists."
4. **A typed error naming the limit**, never a truncated or partial result. A
   partial plaintext from a bounded decrypt is worse than a refusal.
5. **Streaming is not exempt from bounding.** A caller streaming into a buffer
   has exactly the same exposure, so the reader takes an optional total
   plaintext ceiling. Streaming bounds *our* memory to one frame; it does not
   bound the caller's.

**Default ceiling (open to revision):** 1 MiB for the compact record, chosen so
a compact record never exceeds what a single framed frame would hold — which
keeps one invariant across both formats and makes the choice between them a
question about ranged reads rather than about size. Configurable upward
explicitly; a deployment that raises it has said so.

## Adoption

Revised 2026-10-27. The 2026-10-24 version of this section sequenced the
extraction after CAS's ~2026-11-05 alpha; the owner reordered to implement every
module before returning to CAS, so the dependency ran the other way and this
module was what blocked CAS's plan at step 4. **That step is done: CAS adopted
`v0.1.0` on 2026-10-27.** The direction of the dependency now matters in the
other sense — a release of this module that broke the contract CAS deleted its
own implementation for fails CAS's build, which is what the suites are for.

| Consumer | State |
|---|---|
| cas | **adopted, 2026-10-27** — CAS deleted `internal/crypto` (1,442 lines of Go plus a 298-line format spec) and imports this module; `internal/sealconformance` runs `RunStreamSealerSuite` against `seal.Framed()` and `RunRecordSealerSuite` against `seal.Compact()`. Both passed unchanged on the first attempt, with no shim and no skipped subtest, which is the first time either suite ran from outside this module. The cutover was clean because the wire formats are incompatible and CAS had nothing stored. CAS's adoption is also what produced the accounting under *What is not done*: 11 of its 23 retired tests were reachable from its CI, now 16. |
| kgs | **unblocked** — the compact record (format version 2) is implemented, with the `(graph, fact id, attribute)` binding its per-attribute encryption needs (its design §23.1, leak channel #17). |
| acre | not expected |

### What is not done

- **`v0.1.0` is tagged and pinned by CAS**, so `api.txt` is a compatibility
  promise from here on rather than a record of the current surface. Growing it
  is still a reviewed diff; shrinking it is now a breaking change.
- **No external review.** The compact record is new code in a module whose
  whole subject is cryptographic construction, and it has had none. The framed
  format has CAS's review history behind it; version 2 has only this module's
  tests.
- **Seven of CAS's 23 retired tests are still unreachable from a consumer's
  CI**, and each of the seven needs the wire format or the test-only frame-size
  seam: the committed vectors, an altered in-range `frame_size`, the seam's own
  bounds check, `frame_size` honoured from a header, lazy per-frame range
  decryption, a frame count proportional to a range, and the
  authoritative-`size` known limitation. They run here. A suite that reached
  them would have to assume a layout, and would then pass for one
  implementation only.

## Provenance

Raised by the owner 2026-10-23: "shall we at least as an SDK provide encryption
and decryption helpers?" Answer: yes, and as an extraction of CASF1 rather than
new code, plus the compact-record shape CASF1 lacks.
