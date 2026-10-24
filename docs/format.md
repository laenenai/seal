# The SEAL formats

This document is a committed artifact. Each format's `testdata/vectors.json`
pins it with worked examples, and `TestVectors_MatchCommittedTestdata` decrypts
that committed ciphertext directly. A future change to anything described here
must change both this file and the vectors, deliberately — never silently,
since silent drift here means previously stored ciphertext becomes unreadable.

**If a committed ciphertext stops decrypting, that is a real failure, not a
vector to refresh.** A module that regenerates its vectors has thrown the
property away and kept the file.

## Contents

- [Version registry](#version-registry)
- [Not wire-compatible with `cas/internal/crypto`](#not-wire-compatible-with-casinternalcrypto)
- [Format version 1 — the framed stream](#format-version-1--the-framed-stream)
- [Format version 2 — the compact record](#format-version-2--the-compact-record)
- [Key and nonce management at scale](#key-and-nonce-management-at-scale)
- [Size ceilings](#size-ceilings)
- [Errors](#errors)
- [Test vectors](#test-vectors)

---

## Version registry

There is **one numbered version space** covering both wire shapes, not one
counter per shape. A format version names a `(shape, revision)` pair, and the
next change to either shape takes the next number here.

| Version | Shape | Wire discriminator | What its AAD begins with |
|---|---|---|---|
| **1** | framed stream | the 5-byte magic `SEAL1` at the head of the 25-byte header | the whole 25-byte header |
| **2** | compact record | a single leading byte holding `0x02` | the whole 17-byte prefix (version byte + salt) |

The cost of one space is that the numbers no longer read as "revision 1 of the
framed format". What it buys is that a version number is unambiguous on its
own, which is what matters when it is the thing bound into an AEAD tag and the
thing a stored row records. A future reframing of the framed format is **version
3**; a change to the compact record is **version 4**.

Every identifier says the same number this table does — the framed stream's
magic is `SEAL1` and its HKDF info `"SEAL1 frame key"`; the compact record's
wire byte is `2` and its HKDF info `"SEAL2 record key"` — so there is nothing to
keep in step, and a version read off the wire, off a stored column, or out of a
key derivation is the same number spelled the same way.

### There is no shared *stored* prefix, and that is a decision

The framed stream spends five bytes on `SEAL1` because it already has a header
and a blob can afford it. The compact record spends one byte, holding the
version number and nothing else, and does **not** carry the family name.

Making the compact record self-describing in the same way would cost four or
five bytes on every one of potentially tens of millions of short values — a
tenth of the record's whole overhead — for a self-description the caller already
has from the column it read. What a shared prefix would have bought is that a
ciphertext written under one version can never be opened as another, and that is
bought instead by **binding each version number into its own AAD**, which costs
nothing on the wire because AAD is authenticated rather than stored.
`TestTheTwoFormatsAreNotInterchangeable` pins it: a framed stream opened as a
compact record, and a compact record opened as a framed stream, are both
`ErrCorrupt`.

The two formats' HKDF `info` strings differ as well (`"SEAL1 frame key"` and
`"SEAL2 record key"`), so the same DEK used for both derives independent keys
even if a salt value happened to repeat across them.

The cost, stated: a loose 33-byte blob is not identifiable as a compact record
by inspection the way a framed stream is by its magic. Anything holding compact
records knows what they are from the schema that stores them, and a format that
cannot be identified out of context is the price of a format small enough to use
per attribute.

## Not wire-compatible with `cas/internal/crypto`

The framed format is an extraction of `cas/internal/crypto`. The code came
across, the properties came across, and the tests came across under their own
names. **The wire format did not.**

That implementation's magic was `CASF1` and its HKDF info string
`"CASF1 frame key"`. Both are renamed here, to `SEAL1` and
`"SEAL1 frame key"`. Because the magic is bound into every frame's AAD and the
info string determines the frame key, that changes both the keystream and every
tag: **ciphertext written by `cas/internal/crypto` does not decrypt under
`seal`, and ciphertext written by `seal` does not decrypt under
`cas/internal/crypto`.**

This is deliberate, and there is **no compatibility path** — no second accepted
magic, no version shim, nothing to delete later. It cost nothing, because
nothing has ever been persisted: CAS is unreleased and untagged, with no
deployment and no stored blobs, so there is no data to be compatible with.
Carrying another module's spelling forever for the sake of bytes that do not
exist is the kind of debt that is cheapest to refuse on the day it would be
taken on. CAS keeps its own copy until it swaps, at which point it still has
nothing stored.

The practical consequence, for whoever meets it: **a blob whose first five bytes
read `CASF1` was written by CAS's own copy, and this module rejects it as
`ErrCorrupt`.** That is the expected answer, not a bug — and it is the same
answer as for any other wrong magic, because `ErrCorrupt` deliberately never
says which check failed.

The committed vectors were regenerated once, for this rename, and must not be
regenerated again casually. What they protect is **future** drift between this
document and the code, which survives one deliberate regeneration and is lost
only to a careless one. See [Test vectors](#test-vectors).

---

## Format version 1 — the framed stream

Extracted verbatim from `cas/internal/crypto`. Every property below is a bug
somebody already found, and the tests in `internal/framed/framed_test.go` are
CAS's, under their own names.

### Goals

- Detect truncation (a dropped final frame).
- Detect reordering (two frames swapped, or one dropped from the middle).
- Detect any bit flip anywhere in the stream, **including the header**.
- Bind ciphertext to exactly one object of exactly one tenant, so a frame
  cannot be spliced or replayed from one object into another, **even within the
  same tenant**.
- Allow a ranged read to decrypt only the frames it needs, not the whole
  object.

### Layout

```
+--------------------+------------+------------+-----+------------+
| header (25 bytes)  | frame[0]   | frame[1]   | ... | frame[n-1] |
+--------------------+------------+------------+-----+------------+
```

#### Header (25 bytes, fixed)

| field      | size | value                                                 |
|------------|------|-------------------------------------------------------|
| magic      | 5    | ASCII `"SEAL1"`                                        |
| frame_size | 4    | big-endian uint32, the stream's plaintext frame size   |
| salt       | 16   | random, unique per stream                              |

The decoder reads `frame_size` from the header and uses it for every
frame-boundary computation in the rest of this document — it is not hardcoded
to any one value. It must satisfy `MinFrameSize <= frame_size <= MaxFrameSize`
(`64` and `8 MiB` respectively, chosen so the floor bounds how many vanishingly
small frames a hostile header can force the decoder to process, and the ceiling
bounds the memory needed to buffer one frame); a header outside that range is
rejected as `ErrCorrupt` before any frame is touched. The production encoder
always writes `FrameSize` (1<<20, 1 MiB); a smaller `frame_size` is only ever
written by tests, through the package's test-only seam, so that committed
fixtures don't have to be megabytes large to exercise multiple frames.

#### The two mechanisms that cover the header, and why they are two

The header carries **no authentication tag of its own**, and is still
effectively authenticated, because **the entire 25-byte header is bound into
every frame's AAD**: any change to any header byte — magic, `frame_size`, or
`salt` — changes the AAD every frame was sealed under, so every frame fails to
authenticate.

That is load-bearing and **not redundant with** the `[MinFrameSize,
MaxFrameSize]` bounds check above. **The bounds check exists purely to bound
decoder resource use and authenticates nothing.** An out-of-range `frame_size`
is rejected before any frame is touched, so a hostile header cannot force an
enormous number of tiny frames or an oversized frame buffer — and that is all
it does.

Keeping these apart matters because it is exactly the distinction a rewrite
loses. Concretely: before the header was bound into the AAD, a single-frame
object (one shorter than `frame_size`) could have `frame_size` rewritten to any
other in-range value and still decrypt cleanly, because the short-final-frame
path reads whatever ciphertext remains regardless of what `frame_size` claims.
The bounds check was in place the whole time and did not help.
`TestDecrypt_RejectsAlteredInRangeFrameSizeOnSingleFrameObject` reproduces the
exact values a reviewer found decrypting cleanly before the fix.

#### Frames

Every stream has at least one frame, even for a zero-byte object: there is no
such thing as zero frames. Each frame holds up to the header's `frame_size`
plaintext bytes; every frame holds exactly `frame_size` bytes except possibly
the last, which holds whatever remains (0 to `frame_size` bytes) and is always
present. On the wire, a frame is:

```
AES-256-GCM-Seal(plaintext_frame) = ciphertext_frame || 16-byte tag
```

so a full frame is `frame_size + 16` bytes on the wire, and the final frame is
`len(remaining plaintext) + 16` bytes (which may coincidentally equal a full
frame, when the plaintext length is an exact multiple of `frame_size`).

### Key derivation

A single AES-256 key is derived once per stream, shared by every frame:

```
frame_key = HKDF-SHA256(secret = dek, salt = header.salt, info = "SEAL1 frame key", length = 32)
```

`dek` is the caller-supplied data encryption key — a `keyring.DEK`, whose
material is exactly 32 bytes and which this module never persists, wraps or
destroys. The random per-stream salt means the same `dek` reused across two
streams (which should not happen — every object gets its own DEK — but costs
nothing to defend against) still derives unrelated frame keys. It is also what
moves the bound on how many streams one DEK may seal out of the nonce space;
see [Key and nonce management at scale](#key-and-nonce-management-at-scale).

### Nonce

Frame `i`'s 96-bit GCM nonce is `i` as a big-endian integer, zero-extended to
12 bytes:

```
nonce(i) = 0x00000000 || big-endian-uint64(i)
```

This is safe because the frame key is unique per stream (see above) and the
index never repeats within a stream (it increments by exactly one per frame,
bounded well under 2^64), so no `(key, nonce)` pair is ever reused.

### Additional authenticated data (AAD)

Frame `i`'s AAD binds the stream's entire header, the object's address, and the
frame's position in the stream:

```
AAD(i, final) =
    header                                               # all 25 bytes, exactly as written/read: magic, frame_size, salt
    || uint32(len(tenant)) || tenant
    || uint32(len(object)) || object                     # CAS passes a content address's canonical "algo:hex" form
    || uint64(i)                                         # frame index, big-endian
    || (final ? 0x01 : 0x00)                             # final-frame flag
```

Each variable-length field is length-prefixed so the encoding has no ambiguity.
The header is fixed-length and is not length-prefixed; it needs no delimiter
since nothing after it could be mistaken for more header bytes.

**There is no component count, and there must not be one.** This is byte for
byte what CAS's committed vectors were sealed under, and the encoding is
injective without a count only because version 1 fixes the number of address
components at **two**. That is why `ObjectAddress` carries exactly two
components and no more: a third would make the encoding ambiguous, and adding a
count to close that would change every committed tag. (The compact record,
whose address has a variable number of components, *does* encode the count — see
below.)

Binding the *whole* header — not just, say, `frame_size` — is a deliberate
simplicity choice: it authenticates magic, frame size, and salt together, with
one mechanism, so there is no "which header fields are covered by what"
question for the next person to work out.

This is what makes the format's core guarantees hold:

- **Reordering** (two frames swapped, or one dropped from the middle) is
  detected because a frame's authenticated index is fixed at encryption time.
  If frame 1 is moved to where frame 0 was expected, the decoder authenticates
  it against `AAD(0, ...)`, which does not match the `AAD(1, ...)` it was
  actually sealed under, so the GCM tag fails to verify.
- **Truncation** (the final frame is dropped) is detected because the decoder
  only learns a frame is the stream's last by finding EOF immediately after it
  (see the finality peek below). A stream cut short right after a genuine
  non-final frame makes the decoder re-interpret that frame as final, and
  authenticate it against `AAD(i, final=true)` — which never matches the
  `AAD(i, final=false)` tag it was actually sealed under.
- **Cross-object splicing or replay** (taking a frame from one object and
  inserting it into another object of the same tenant) is detected because the
  object component is part of the AAD. The same reasoning covers cross-tenant
  replay via the tenant component.

### Decoding and the finality peek

The ciphertext alone cannot say whether a given frame is the stream's last,
since the writer does not reserve any out-of-band marker for it — finality is
only expressed inside each frame's AAD, which must be known *before* attempting
to authenticate that frame. The decoder resolves this by reading one candidate
frame's worth of ciphertext (`frame_size + 16` bytes) and then:

- if fewer than `frame_size + 16` bytes were available, this is necessarily the
  short final frame;
- otherwise, it peeks one more byte from the underlying stream: if that peek
  hits EOF, this full-length frame is the stream's last; if more data follows,
  it is not.

Only after that is the frame opened, with the AAD's `final` flag set
accordingly. This peek is also exactly what makes the truncation defense work:
dropping the true final frame makes the decoder's peek find EOF one frame
early.

A streaming decode (`NewDecryptReader`) therefore authenticates frames in order
as the caller reads them, while `NewDecryptRangeReader` instead computes, from
the caller-supplied total stream `size`, exactly which frame indices overlap
`[off, off+length)` and opens only those — one at a time, as the caller reads,
holding at most one frame's plaintext in memory — each with the correct index
and the correct `final` flag for its true position in the stream. This keeps
both the I/O and the memory a ranged read costs proportional to the requested
range, not to the size of the object.

### The range reader's integrity depends entirely on a trustworthy `size`

`NewDecryptRangeReader`'s every correctness check — how many frames the stream
has, which frame is final, the plaintext length a requested range is validated
against — is derived from the caller-supplied `size`, never rediscovered from
the ciphertext itself (rediscovering it would mean reading the whole object,
defeating the point of a ranged read). This means **`size` must be the object's
authoritative stored ciphertext length, taken from the metadata store, never a
length reported by the object store or blob backend at read time.**

An attacker who can truncate (or extend) the stored ciphertext, and who can
also make the reported size match that truncation, can make any range read that
never touches the altered part of the object succeed and authenticate perfectly
— the range reader has no way to learn the object used to be a different size.
This is a deliberate scope limit, not a bug: only a full, sequential
`NewDecryptReader` pass authenticates an object end to end, and that is exactly
the cost a ranged read exists to avoid paying.
`TestRangeReader_SizeMustBeAuthoritative_KnownLimitation` pins it so a future
change that makes the range reader *even less* likely to notice such tampering
does not slip by unremarked.

`size` is also trusted not to be absurd: `numFrames` is computed from it
without an overflow guard. A caller-supplied `off` and `length`, by contrast,
*are* guarded, because those arrive from untrusted input — an HTTP `Range`
header — and `off+length` can wrap a negative int64 straight into an allocation
sized by the wrapped result.

### Partial reads and `Close`

`NewDecryptReader` returns an `io.ReadCloser`, not a bare `io.Reader`: `Read`
authenticates frames one at a time as the caller consumes them, but a caller
that stops reading early must not be left thinking the object is fine when a
later frame is corrupt. `Close` drains and authenticates every frame the caller
never read, and returns `ErrCorrupt` if any of them fail. **A caller must check
`Close`'s error even after a successful `Read`.**

This guarantee has a cost that is easy to miss: because `Close` decrypts and
authenticates everything the caller didn't read, closing a reader that
abandoned a read partway through a large object **costs as much as decrypting
the rest of that object**. A client that opens a multi-gigabyte download and
disconnects after the first few bytes makes the server's `Close` call pay to
decrypt the remaining gigabytes. A download path that lets clients disconnect
mid-read should account for this explicitly — by not calling `Close`
synchronously on the request's goroutine, or by choosing not to drain at all
for an abandoned request where the integrity check no longer serves anyone —
rather than assume `Close` is cheap.

### Constants

- `FrameSize = 1 << 20` (1 MiB of plaintext per frame; what the production
  encoder always uses).
- `MinFrameSize = 64`, `MaxFrameSize = 8 * 1024 * 1024`.
- AES-256-GCM: 32-byte key, 12-byte nonce, 16-byte tag.
- Header: 25 bytes (5-byte magic, 4-byte frame size, 16-byte salt).

---

## Format version 2 — the compact record

The one format in this module that is new rather than extracted.

### Why it exists

Version 1's 25-byte header plus a 16-byte tag per frame is 0.004% overhead on a
1 MiB blob and **over 200% on a 20-byte fact literal**. `kgs` encrypts per
attribute, which means potentially tens of millions of short values, so the
framed format is the wrong tool there.

### Layout

```
+---------+------------+--------------------+----------+
| version | salt (16)  | ciphertext         | tag (16) |
|  (1)    |            |                    |          |
+---------+------------+--------------------+----------+
```

| field      | size   | value                                   |
|------------|--------|-----------------------------------------|
| version    | 1      | `0x02`, the format version in the registry above |
| salt       | 16     | random, unique per record                |
| ciphertext | len(pt)| AES-256-GCM keystream output             |
| tag        | 16     | AES-256-GCM tag                          |

Total overhead: **33 bytes**. There is no stored nonce (it is derived) and no
framing.

### What the size win actually is, stated rather than implied

| plaintext | framed stream | compact record |
|---|---|---|
| 20 B | 61 B (205% overhead) | 53 B (165% overhead) |
| 1 KiB | 1065 B (4.0%) | 1057 B (3.2%) |
| 1 MiB | 1048617 B (0.004%) | 1048609 B (0.003%) |

Eight bytes, not an order of magnitude. The derived nonce saves twelve and the
absent framing costs four more in the version byte and the arithmetic. What
actually makes the compact record the right tool for tens of millions of short
values is that it costs **one AEAD operation and no framing state**, and that
the thing it binds to is an arbitrary address rather than a `(tenant, object)`
pair — not that it is small.

### Key and nonce derivation

One HKDF expansion produces both:

```
okm        = HKDF-SHA256(secret = dek, salt = record.salt, info = "SEAL2 record key", length = 44)
record_key = okm[0:32]
nonce      = okm[32:44]
```

The nonce **could** equally be twelve zero bytes, since the key is already
unique per record. Deriving it from the same expansion costs nothing, stores
nothing, and keeps the construction sound if the key derivation is ever changed
to be shared across records — which is exactly the change someone makes for
performance without re-reading the reasoning.

The salt is **random per record** and stored. Deriving it from the address
instead, which would remove all 16 bytes from the wire, was considered and
rejected: the key would then be unique per *address* rather than per record, so
re-encrypting the same attribute after an update would reuse the same
`(key, nonce)` pair with different plaintext. That is catastrophic GCM nonce
reuse — the keystream XOR discloses both plaintexts and the authentication key
becomes recoverable — and it would be reached by an ordinary attribute update,
not by an attack. Sixteen bytes is the right price for not having that footgun.

### Additional authenticated data (AAD)

```
AAD =
    prefix                                               # all 17 bytes: the version byte and the salt, exactly as written/read
    || uint32(n)                                         # number of address components
    || uint32(len(part[0])) || part[0]
    || ...
    || uint32(len(part[n-1])) || part[n-1]
```

Binding the whole prefix rather than picking out the version byte is version
1's rule applied again: all of it is covered, uniformly, so there is no "which
prefix bytes are authenticated" question. The salt is already bound through the
key derivation, so including it here is belt and braces; **the version byte is
bound here and nowhere else**, which is what makes a version-2 record
impossible to open as a future version 4 even if the layouts were otherwise
compatible.

**The component count is encoded, and here it must be.** Length-prefixed
concatenation is injective at a fixed arity — which is all version 1 needs —
but not across differing arities. Without the count, `("ab", "c")` and some
other arrangement of the same bytes could encode identically, so an address
could be re-split and still authenticate.
`TestOpen_RefusesAnAddressThatSplitsTheSameBytesDifferently` pins it.

### The binding is the point, not an optimisation

Generalised from version 1's object binding, a `kgs` attribute value binds to
`(graph, fact id, attribute)`. Without that, an encrypted `salary` value can be
**relocated onto another row** — by a bug, or by anyone with database write
access — and will decrypt cleanly to the wrong answer. With it, relocation is a
decryption failure. This is recorded as **leak channel #17** in the `kgs`
design.

`RefusesRelocationToAnotherAddress` varies every component independently,
because a binding that covers two of three is a binding that lets the third be
rewritten. Order is significant and part of the binding, so a value cannot be
moved between two columns whose names happen to be each other's.

### Address component rules

Both address types validate every component: non-empty, at most 256 bytes,
valid UTF-8, no path separators, null bytes, control characters or surrounding
whitespace, and not a relative path element. A record address carries 1 to 16
components.

The rules are deliberately stricter than the AEAD needs — GCM would bind any
byte string — because the same component is a database key, an object-store
name and an audit-log field, and the safe set is the intersection of what all
of those accept rather than the union. They are the same rules `keyring`
applies to a KEK id and a key id, for the same reason. A colon is allowed, and
has to be: CAS's object component is a content address's canonical
`"<algo>:<hex>"` form.

Both types are structs with unexported fields, reachable only through a
validating constructor. The cost is stated rather than discovered: an address
cannot be a map key written as a literal, cannot be built from a database
column without going through its constructor, and **must never be given
`sql.Scanner` or `driver.Valuer`** — those methods are exported, so any package
could then construct one from an arbitrary string, which destroys exactly the
property the type exists for.

---

## Key and nonce management at scale

A single DEK encrypting ten million small records is well inside the territory
where random 96-bit nonces need an argument rather than a citation. So both
formats derive a per-unit key from a per-unit 128-bit random salt — version 1
per stream, version 2 per record — which is what `keyring`'s local adapter
already does for the analogous problem.

### The arithmetic

Each unit's key is used for exactly one plaintext (version 2) or for one stream
whose frame indices never repeat (version 1). So a `(key, nonce)` pair repeats
**only if two units draw the same salt.** With a 128-bit salt and `q` units,
the birthday bound is

```
P(collision) ≈ q(q-1) / (2 · 2^128) ≈ q² / 2^129
```

Setting that equal to a `2^-32` risk target:

```
q² / 2^129 = 2^-32
q²         = 2^97
q          = 2^48.5 ≈ 3.98 × 10^14
```

The baseline it replaces — one key per DEK with an independent random 96-bit
nonce per message — gives

```
P(collision) ≈ q² / 2^97 = 2^-32
q²                       = 2^65
q                        = 2^32.5 ≈ 6.07 × 10^9
```

| construction | records per DEK at a 2^-32 collision risk |
|---|---|
| one key, random 96-bit nonce | ≈ 2^32.5 ≈ 6.1 × 10^9 |
| per-record key from a 128-bit salt | ≈ 2^48.5 ≈ 4.0 × 10^14 |

**A factor of 2^16 = 65,536.** At `kgs`'s stated scale of ten million records
per DEK the collision probability is `(10^7)² / 2^129 ≈ 1.5 × 10^-25`.

### What this is not

It is **not "uncapped"**. The number is 2^48.5 rather than unbounded, and the
honest claim is the comparison, not an absolute. What the per-unit salt buys is
that the cap is four and a half orders of magnitude above anything a deployment
will reach, instead of one order above it — a DEK doing 6 billion records is a
DEK that a busy `kgs` graph could plausibly approach over years, and a DEK
doing 400 trillion is not.

Two further limits, both far out of reach and stated so nobody has to rederive
them:

- **Per invocation.** AES-GCM's plaintext limit for one `(key, nonce)` pair is
  2^39 − 256 bits (about 64 GiB). A compact record is bounded by its ceiling (1
  MiB by default) and a frame by `MaxFrameSize` (8 MiB).
- **Frames per stream.** A frame index is a 64-bit counter, so a stream is
  bounded at 2^64 frames; at 1 MiB each that is 2^84 bytes.

### Where the salt is *not* sufficient on its own

The per-stream salt makes two streams' keys independent; it does **not** make
two uses of the same DEK safe if the caller re-encrypts the same object and
overwrites the old ciphertext while an attacker holds the old copy. That is a
key-lifecycle question, and it belongs to `keyring` and to the consumer, not
here: this module's contract is that it never reuses a `(key, nonce)` pair of
its own accord.

---

## Size ceilings

Every one-shot entry point carries a `Limits`, and the streaming framed reader
carries a total plaintext ceiling. Five rules, and each is a security control
rather than a courtesy.

1. **Two separate limits, not one.** `MaxPlaintext` bounds the encrypt side —
   what a caller may hand us. `MaxCiphertext` bounds the decrypt side, and it
   is the one that matters, because **an attacker controls the ciphertext's
   length**. Only a pair can express "generous on the way in, strict on the way
   out".
2. **Checked before allocation**, from the declared or derivable length — never
   by reading and discovering. This is the allocation-bomb pattern. It is kept
   **distinct** from version 1's `frame_size` bound, which authenticates
   nothing and bounds decoder resource use; two mechanisms.
3. **Fail closed on an unknown length.** If a ceiling is configured and the
   input length cannot be established up front, the operation is refused with
   `ErrUnknownLength`. Deliberately the same rule as CAS §9.2's
   `MaxContentLength` caveat, which fails closed on an unknown length: a
   chunked upload with no declared size is refused when a limit caveat exists.
   The length probe accepts a `Len` method, a `Stat` on a regular file, or a
   `Seek` to the end; a network connection, an HTTP body or a pipe cannot say,
   and is refused rather than read.
4. **A typed error naming the limit**, never a truncated or partial result.
   `*LimitError` names which ceiling and both numbers, and matches
   `ErrLimitExceeded`. A refused call returns **no** bytes: a partial plaintext
   from a bounded decrypt is worse than a refusal, because the caller then holds
   something plaintext-shaped that is not the plaintext.
5. **Streaming is not exempt.** `NewDecryptReader` takes a total plaintext
   ceiling, checked against each frame's wire length *before* that frame is
   opened. Streaming bounds *this module's* memory to one frame; it does not
   bound the caller's.

### Zero, and the default

A zero `Limits` field means **this entry point's default**, not "unbounded".
That is the one decision in the type that has to be right: the zero value is
what a caller gets when they forget, and forgetting must not switch a security
control off. `Unlimited` must be written out.

The default is **1 MiB**, chosen so a compact record never exceeds what a
single framed frame would hold — which keeps one invariant across both formats
and makes the choice between them a question about **ranged reads** rather than
about size. It is open to revision; the reasoning is the part worth keeping.

**Both ceilings are enforced on decrypt**, each on the thing it names: the
ciphertext ceiling against the input's length, and the plaintext ceiling
against the length the input declares by being as long as it is. The derived
default normally makes the two agree, so the difference only shows when a
caller opts one of them out by hand — and reading `MaxCiphertext: Unlimited`
with a `MaxPlaintext` still in place as "no bound on either" would be the
surprising answer rather than the safe one.

`MaxCiphertext`, left zero, is derived from `MaxPlaintext` plus the format's
overhead, so a caller that raises one ceiling is not left unable to read back
what it just wrote. The derivation differs per format — a flat 33 bytes for the
compact record, a header plus one tag per frame for the framed stream — which
is why `Limits` has `ResolveCompact` and `ResolveFramed` rather than one method
taking a flat number. The framed derivation is one tag generous at exact
multiples of `FrameSize`; a ceiling that is 16 bytes loose is the right side to
be wrong on.

The streaming reader's ceiling is the one place a **zero is refused** rather
than defaulted, with `ErrInvalidLimit`. A whole-value one-shot has a defensible
default; a stream does not, because the framed format exists for objects whose
size is not known in advance. With no default to fall back on, the choice is
between refusing a zero and treating it as unbounded, and refusing is the one
nobody arrives at by forgetting.

---

## Errors

- **`ErrCorrupt`** — a ciphertext authentication failure: a flipped bit, a
  dropped or reordered frame, a truncated stream, a tampered header, a record
  relocated to another address, an unrecognised format version byte, or an
  address that does not match what the ciphertext was sealed under. **It never
  carries detail about which**, because naming the failing check hands an
  attacker a dimension to search along. In particular, "this is a version 1
  stream, not a version 2 record" is *not* reported as such.
- **`ErrInvalidDEK`** — the DEK holds no usable key material: the zero value,
  one already destroyed, or one whose shared backing array was zeroized through
  another copy. `keyring.DEK` makes the length cases unconstructible, which is
  narrower than the extracted code's check needed when the DEK was a bare
  `[]byte`.
- **`ErrInvalidAddress`** — an address component is not safe to bind, or the
  address is the zero value.
- **`ErrRange`** — a ranged read's `off`/`length` was negative, or the range
  falls outside the object's plaintext size. Distinct from `ErrCorrupt` so an
  HTTP range handler can tell "respond 416" from "respond 500" without matching
  on error text.
- **`ErrClosed`** — a write after `Close` already sealed the final frame or the
  record's single tag.
- **`ErrInvalidFrameSize`** — a `frame_size` outside `[MinFrameSize,
  MaxFrameSize]` supplied to version 1's internal constructor. Reachable only
  through the test-only seam today.
- **`ErrLimitExceeded`** — the sentinel every `*LimitError` matches.
- **`ErrUnknownLength`** — a ceiling is configured and the input's length could
  not be established before reading it.
- **`ErrInvalidLimit`** — a ceiling that is neither `Unlimited`, nor zero, nor
  a positive byte count; or a zero passed as a stream's ceiling.

---

## Test vectors

### Version 1 — `internal/framed/testdata/vectors.json`

Generated once, deliberately, by `gen_vectors_test.go -write-framed-vectors`,
each with a fixed DEK and a fixed salt so the ciphertext is reproducible. The
generator is in the tree so the provenance of the committed bytes is auditable —
which DEK, which salt, which frame size, which address — **not** so a failing
vector has somewhere to be regenerated from. It skips by default.

These are **not** CAS's bytes; see
[Not wire-compatible with `cas/internal/crypto`](#not-wire-compatible-with-casinternalcrypto).
Everything that is not the wire format — the DEKs, salts, frame sizes, tenant
and content addresses — is CAS's original fixture unchanged, so that the diff
which regenerated this file shows the format changing and little else; the only
other change is the first vector's plaintext, an ASCII sentence that used to
name CAS.

It commits a `"vectors"` array, not a single fixture, because one small
single-frame vector is byte-identical under several wire format changes that
should be caught — nonce endianness, AAD index endianness, a different
final-flag encoding, a different wire stride, a changed finality rule all
happen to agree with a single vector whose only frame has index 0 and
`final=true`. The committed vectors cover:

- a single frame at index 0 with `final=true` (the original, smallest case),
  encrypted at the production `FrameSize`;
- three frames at a small test-only `frame_size`, covering `final=false`, a
  frame index greater than zero, and a short final frame.

The three-frame vector's discriminating power was verified in CAS directly
against a decoder built from the format document alone: it rejects a decoder
that uses little-endian nonces, little-endian AAD frame indices, a different
final-flag encoding, a different wire stride, or an "every frame is final" rule,
where the single-frame vector by itself catches only one of those five. The
rename changed the bytes, not the shape, so that reasoning carries over
unchanged: the vector is still one stream of three frames at a small frame size,
covering `final=false`, an index above zero, and a short final frame.

### Version 2 — `internal/compact/testdata/vectors.json`

Generated once, deliberately, by `gen_vectors_test.go -write-compact-vectors`,
each with a fixed DEK and a fixed salt. The generator is kept in the tree so the
provenance of the committed bytes is auditable — which DEK, which salt, which
address — **not** so a failing vector has somewhere to be regenerated from. It
skips by default.

Three vectors are committed, because one cannot discriminate:

- a three-component address over a twenty-byte fact literal, which is the shape
  `kgs` actually writes;
- an empty value, which exercises a record with no ciphertext body at all;
- a single-component address over binary bytes including `0x00`, `0x7f`, `0x80`
  and `0xff`, which exercises the AAD's component count at `n = 1` and would
  catch a plaintext that was somehow text-normalised.

`salt_hex` is recorded only for provenance; the decoder reads the salt from the
record itself, as every real reader does.

### The rule, for both

`TestVectors_MatchCommittedTestdata` decrypts every entry's `ciphertext_hex`
directly. **It must never be replaced by re-encrypting `plaintext_hex` and
comparing**, since the whole point is to catch a silent format change that a
round trip cannot.
