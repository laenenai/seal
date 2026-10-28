# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository. Do not open a public issue with vulnerability details.

Include the affected version or commit, a minimal reproducer, the impact you
believe is possible, and any mitigation you know of. If private reporting is
unavailable, open a minimal public issue asking for a private channel and do not
include details.

## Supported versions

| Version | Security fixes |
|---|---|
| `v0.2.x` (latest minor) | Yes |
| `v0.1.x` | Best effort only; CAS pins `v0.1.0`, but fixes land on the latest minor |
| Earlier | No |

`seal` is pre-1.0. A minor release may contain API changes. Upgrade to the
latest minor to receive security fixes.

## Response targets

- **Acknowledgement:** within 3 business days.
- **Triage:** within 7 business days, including a severity assessment and a
  proposed next step.
- **Coordinated disclosure:** within 90 days of the report. We will agree a
  disclosure date with the reporter and may extend it when a fix or deployment
  needs more time.
- We will credit reporters in the advisory unless they ask to remain anonymous.
- There is no bug bounty.

## Security model

`seal` encrypts and decrypts opaque bytes under a caller-supplied data
encryption key. It uses AES-256-GCM with a per-stream or per-record key derived
via HKDF-SHA256 from a random 128-bit salt, and binds each ciphertext to an
address in the AEAD's additional authenticated data.

### What it guarantees

- **Confidentiality without the DEK.** Ciphertext does not reveal the
  plaintext to someone who does not hold the key.
- **Integrity and authenticity.** A modified ciphertext, tag, header, version
  byte, or address fails authentication.
- **Placement integrity.** A compact record moved to another address, or a
  framed stream moved to another `(tenant, object)`, fails to decrypt rather
  than decrypting to the wrong answer.
- **Sequence integrity for framed streams.** Dropped, reordered, or truncated
  frames fail; the header is bound into every frame's AAD.
- **Bounded reads.** One-shot entry points check their configured ceilings
  before allocation, fail closed on an unknown length, and return no plaintext
  on refusal. Streaming readers bound this module's memory to one frame.

### What it does not guarantee

- **Key management or the DEK lifecycle.** Generation, wrapping, storage,
  rotation, and destruction belong to `keyring` (or another key manager).
- **Rollback or freshness.** A previously valid ciphertext replayed at the same
  address still decrypts. If rollback matters, bind an application version or
  epoch into the address or check trusted metadata before decrypting.
- **Whole-object integrity for a ranged read.** `NewDecryptRangeReader` derives
  its checks from the caller-supplied `size`. A range that does not reach a
  truncated tail can authenticate. Use a full sequential read when whole-object
  integrity is required, and source `size` from metadata the data owner cannot
  retroactively change.
- **Address uniqueness.** The consumer must pass a stable address that uniquely
  identifies the value for its lifetime. A mutable path, display name, or
  colliding identifier defeats the placement binding.
- **Zeroization of derived material.** Destroying the `keyring.DEK` does not
  wipe HKDF-derived keys, AES key schedules, or decrypted plaintext buffers.
  Redaction prevents formatting leaks, not memory disclosure.
- **Side-channel resistance.** No timing or cache side-channel analysis has
  been performed.
- **Authorization or policy.** `seal` has no notion of who may decrypt what;
  that belongs to the key manager and the application.

### Consumer obligations

Consumers must use unique, stable addresses; choose ceilings appropriate to
their data; check `Close` on framed readers; treat a streaming limit error as a
partial result; and source ranged-read sizes from authoritative metadata. See
[`examples/README.md`](examples/README.md) for the operational version of these
rules.

## External review status

The module has **not had an independent external security or cryptographic
review**. The framed format carries review history from `cas/internal/crypto`;
the compact record (SEAL2) is new in this module. An independent review of SEAL2
is the remaining external gate before a production or v1.0 recommendation.
This document and the committed format specification are written so that review
can proceed without reading the implementation first.

## What the conformance suite proves, and what it does not

Each port in this module ships a conformance suite that every adapter must
pass, and the suite — not the interface — is the authoritative description of
the contract. Security invariants have their own named subtests, so an adapter
cannot quietly skip one.

The suite proves the *contract*. It cannot prove *enforcement* that belongs to
something outside this process: a database's row-level security, a key
manager's access policy, an operator's privilege separation. Those are the
deployment's responsibility. Where that line falls is stated in the package
documentation rather than left to be assumed.
