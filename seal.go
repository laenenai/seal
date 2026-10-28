// Package seal encrypts and decrypts opaque bytes under a caller-supplied
// data encryption key, in a versioned, vector-pinned format whose ciphertext
// is bound to the one place it belongs.
//
// What it does not do, per CHARTER.md: key management, wrapping or custody
// (that is keyring, and escrow for keyring's key-encryption keys); anything
// about what the bytes mean; the DEK's lifecycle; policy of any kind.
//
// # The property that matters
//
// The AEAD's additional authenticated data binds ciphertext to its address. A
// value moved from one row to another — by a bug, or by anyone with database
// write access — becomes a decryption failure rather than a silent wrong
// answer. Confidentiality without integrity of placement is not enough: an
// encrypted salary relocated onto a colleague's row decrypts perfectly and
// answers the wrong question, and no amount of key hygiene prevents that.
//
// # Two shapes, one format family, one version space
//
// Format is chosen by whether ranged reads are needed; API shape by where the
// bytes are.
//
//   - A framed stream (format version 1) for blobs and anything read by
//     range: NewEncryptWriter, NewDecryptReader, and NewDecryptRangeReader,
//     which decrypts only the frames a requested range overlaps. It detects
//     truncation of the final frame, reordering, and any bit flip including in
//     the header. EncryptObject and DecryptObject are the bounded one-shot
//     convenience over it.
//   - A compact record (format version 2) for a whole small value:
//     EncryptRecord and DecryptRecord, with NewRecordWriter and NewRecordReader for
//     a caller holding an io.Reader or io.Writer. 33 bytes of overhead against
//     41 for a single-frame stream, no framing, a derived nonce, and an
//     address that is an ordered list of components rather than a (tenant,
//     object) pair.
//
// Both versions live in one numbered space rather than one counter per shape,
// and each version is bound into its own AAD, so a ciphertext written under one
// can never be opened as another. The identifiers say the same number the
// registry does: the framed stream's magic is "SEAL1", the compact record's
// wire discriminator is the byte 2, and their HKDF info strings are
// "SEAL1 frame key" and "SEAL2 record key".
//
// The framed format is an extraction of cas/internal/crypto and its wire format
// is deliberately not compatible with it: CAS's magic and info string were
// CASF1, both are renamed here, and there is no shim. Nothing had ever been
// persisted, so there was nothing to be compatible with. See docs/format.md.
//
// # The size ceilings are security controls
//
// Every one-shot entry point carries a Limits, and the streaming framed reader
// carries a total plaintext ceiling. Two separate ceilings, because an
// attacker controls a ciphertext's length and not a plaintext's; checked
// before allocation from a declared length, never by reading and discovering;
// failing closed with ErrUnknownLength when a ceiling is in force and the
// length cannot be established; refusing with a typed *LimitError rather than
// returning a partial result. The default is 1 MiB, and a zero Limits field
// means that default rather than "unbounded" — an unfinished struct literal
// must not switch a security control off.
//
// # There is no DEK constructor here, and that is the decision
//
// DEK is keyring.DEK aliased, and nothing in this package builds one. There is
// no seal.NewDEK and there will not be: generating, wrapping, storing,
// rotating and destroying key material is keyring's entire subject, and
// CHARTER.md disclaims all of it. A constructor here would advertise a
// capability this module must never own, and a caller who reached for it would
// be left holding a key with nowhere to put it — the wrapped copy, the KEK
// that wrapped it and the column it lives in are all keyring's.
//
// The consequence is stated plainly rather than left to be discovered,
// because it was discovered: a consumer that generates its own data keys
// requires keyring directly. That is intended. keyring owning key
// construction is the point of the split, and a forwarding constructor here
// would hide a real dependency rather than remove one — the type is keyring's
// either way, and so are its validation rules and its errors.
//
// A consumer that only runs the conformance suites needs no direct keyring
// require, since the suites build their own DEKs; the moment it writes a test
// of its own against seal, it would. For that case the fixture is
// sealtest.NewDEK, in the test-support package that already depends on
// keyring — which is where a test fixture belongs, rather than in the
// production API of the module under test.
//
// # Wiring it
//
//	dek, err := km.UnwrapDEK(ctx, wrapped) // keyring
//	if err != nil {
//		return err
//	}
//	defer dek.Destroy()
//
//	addr, err := seal.NewRecordAddress(graphID, factID, "salary")
//	if err != nil {
//		return err
//	}
//	record, err := seal.EncryptRecord(dek, addr, []byte(value), seal.Limits{})
//
// # This file
//
// Every value object lives in internal/domain and nowhere else; the framed
// format in internal/framed, the compact record in internal/compact. This
// file re-exports what a consumer must name as type aliases, so a
// RecordAddress this module produces and a seal.RecordAddress a consumer holds
// are the identical type, and it carries the module's entry points — every
// function here is a short forward to an internal package. It holds no logic
// beyond resolving a Limits once at the boundary.
//
// There is no Clock and no timestamp anywhere in this module, and no
// CanonicalTime copy: nothing here records when anything happened. There is no
// Open(ctx, Config) constructor either, because there is nothing to configure
// and nothing to connect to — the ports below exist for the conformance suite
// and for a consumer swapping in its own implementation, not because this
// module performs I/O.
package seal

import (
	"bytes"
	"io"
	"math"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/compact"
	"github.com/laenenai/seal/internal/domain"
	"github.com/laenenai/seal/internal/framed"
)

type (
	// DEK is one data encryption key, zeroizable and non-rendering. It is
	// keyring's type, aliased rather than wrapped, so a DEK a key manager
	// returns and a seal.DEK are the identical value. This module never
	// generates, wraps, stores or destroys one, and offers no constructor for
	// one — see the package comment's "There is no DEK constructor here" for
	// what that means for a consumer's go.mod.
	DEK = keyring.DEK

	// ObjectAddress is what a framed stream's ciphertext is bound to: exactly
	// one object of exactly one tenant. See domain.ObjectAddress.
	ObjectAddress = domain.ObjectAddress
	// RecordAddress is what a compact record's ciphertext is bound to: an
	// ordered list of components naming the one place the value belongs. See
	// domain.RecordAddress.
	RecordAddress = domain.RecordAddress

	// Limits is the pair of size ceilings every one-shot entry point carries.
	// See domain.Limits — in particular why a zero field means the default and
	// not "unbounded".
	Limits = domain.Limits
	// LimitError is the typed error a ceiling produces, naming which one was
	// exceeded. See domain.LimitError.
	LimitError = domain.LimitError

	// Version is a format version in the module's single version space. See
	// domain.Version.
	Version = domain.Version
)

const (
	// VersionFramed is format version 1, the framed stream.
	VersionFramed = domain.VersionFramed
	// VersionCompact is format version 2, the compact record.
	VersionCompact = domain.VersionCompact

	// FrameSize is the plaintext bytes per frame a framed stream writes.
	FrameSize = domain.FrameSize
	// MinFrameSize is the smallest frame_size a decoder accepts from a
	// stream's header, and MaxFrameSize the largest. The bound exists purely
	// to bound decoder resource use and authenticates nothing; what
	// authenticates the header is that all of it is bound into every frame's
	// AAD. Two mechanisms, kept distinct.
	MinFrameSize = domain.MinFrameSize
	// MaxFrameSize is the largest frame_size a decoder accepts. See
	// MinFrameSize.
	MaxFrameSize = domain.MaxFrameSize

	// CompactOverhead is what a compact record costs over its plaintext: 33
	// bytes, against 41 for a single-frame framed stream.
	CompactOverhead = domain.CompactOverhead

	// Unlimited disables a ceiling, and must be written out: a zero means the
	// entry point's default, so forgetting can never switch a ceiling off.
	Unlimited = domain.Unlimited
	// DefaultMaxPlaintext is the ceiling a one-shot entry point applies when
	// none is configured: 1 MiB, chosen so a compact record never exceeds what
	// a single frame would hold.
	DefaultMaxPlaintext = domain.DefaultMaxPlaintext

	// Redacted is the placeholder every rendering of a type holding derived
	// key material or plaintext yields.
	Redacted = domain.Redacted
)

// Sentinel errors returned across every package boundary in seal. See
// internal/domain/errors.go for their full documentation, in particular why
// ErrCorrupt is deliberately uninformative.
var (
	// ErrCorrupt is domain.ErrCorrupt.
	ErrCorrupt = domain.ErrCorrupt
	// ErrInvalidDEK is domain.ErrInvalidDEK.
	ErrInvalidDEK = domain.ErrInvalidDEK
	// ErrInvalidAddress is domain.ErrInvalidAddress.
	ErrInvalidAddress = domain.ErrInvalidAddress
	// ErrRange is domain.ErrRange.
	ErrRange = domain.ErrRange
	// ErrClosed is domain.ErrClosed.
	ErrClosed = domain.ErrClosed
	// ErrInvalidFrameSize is domain.ErrInvalidFrameSize.
	ErrInvalidFrameSize = domain.ErrInvalidFrameSize
	// ErrLimitExceeded is domain.ErrLimitExceeded.
	ErrLimitExceeded = domain.ErrLimitExceeded
	// ErrUnknownLength is domain.ErrUnknownLength.
	ErrUnknownLength = domain.ErrUnknownLength
	// ErrInvalidLimit is domain.ErrInvalidLimit.
	ErrInvalidLimit = domain.ErrInvalidLimit
)

// NewObjectAddress returns the address a framed stream binds to, or
// ErrInvalidAddress if either component is unsafe to bind. See
// domain.NewObjectAddress.
//
// It delegates rather than being an alias because Go has no alias for a
// function, and a consumer outside this module cannot reach internal/domain to
// call it — nor construct an address any other way, since the components are
// unexported on purpose.
func NewObjectAddress(tenant, object string) (ObjectAddress, error) {
	return domain.NewObjectAddress(tenant, object)
}

// NewRecordAddress returns the address a compact record binds to, or
// ErrInvalidAddress if there are no components, too many, or any one of them
// is unsafe to bind. See domain.NewRecordAddress.
func NewRecordAddress(parts ...string) (RecordAddress, error) {
	return domain.NewRecordAddress(parts...)
}

// StreamSealer is the port the framed format implements: the entry points a
// consumer needs for blobs and for anything read by range.
//
// It exists so that a consumer can run the conformance suite
// (sealtest.RunStreamSealerSuite) against its own implementation rather than
// only against this module's — which is what makes "cas has adopted seal"
// testable instead of asserted, and what lets CAS run the suite against its
// own internal/crypto on the way to swapping it out.
//
// The suite, not this interface, is the authoritative description of the
// contract's edge-case behaviour.
type StreamSealer interface {
	NewEncryptWriter(w io.Writer, dek DEK, addr ObjectAddress) (io.WriteCloser, error)
	NewDecryptReader(r io.Reader, dek DEK, addr ObjectAddress, maxPlaintext int64) (io.ReadCloser, error)
	NewDecryptRangeReader(
		ra io.ReaderAt, size int64, dek DEK, addr ObjectAddress, off, length int64,
	) (io.Reader, error)
	EncryptObject(dek DEK, addr ObjectAddress, plaintext []byte, limits Limits) ([]byte, error)
	DecryptObject(dek DEK, addr ObjectAddress, ciphertext []byte, limits Limits) ([]byte, error)
}

// RecordSealer is the port the compact format implements: the entry points a
// consumer needs for whole small values. See StreamSealer for why the ports
// exist, and sealtest.RunRecordSealerSuite for the contract.
type RecordSealer interface {
	EncryptRecord(dek DEK, addr RecordAddress, plaintext []byte, limits Limits) ([]byte, error)
	DecryptRecord(dek DEK, addr RecordAddress, record []byte, limits Limits) ([]byte, error)
	NewRecordWriter(w io.Writer, dek DEK, addr RecordAddress, limits Limits) (io.WriteCloser, error)
	NewRecordReader(r io.Reader, dek DEK, addr RecordAddress, limits Limits) (io.Reader, error)
}

// Framed returns this module's StreamSealer: format version 1, every method a
// forward to the package-level function of the same name.
func Framed() StreamSealer { return framedSealer{} }

// Compact returns this module's RecordSealer: format version 2, every method a
// forward to the package-level function of the same name.
func Compact() RecordSealer { return compactSealer{} }

type framedSealer struct{}

func (framedSealer) NewEncryptWriter(w io.Writer, dek DEK, addr ObjectAddress) (io.WriteCloser, error) {
	return NewEncryptWriter(w, dek, addr)
}

func (framedSealer) NewDecryptReader(
	r io.Reader, dek DEK, addr ObjectAddress, maxPlaintext int64,
) (io.ReadCloser, error) {
	return NewDecryptReader(r, dek, addr, maxPlaintext)
}

func (framedSealer) NewDecryptRangeReader(
	ra io.ReaderAt, size int64, dek DEK, addr ObjectAddress, off, length int64,
) (io.Reader, error) {
	return NewDecryptRangeReader(ra, size, dek, addr, off, length)
}

func (framedSealer) EncryptObject(dek DEK, addr ObjectAddress, plaintext []byte, limits Limits) ([]byte, error) {
	return EncryptObject(dek, addr, plaintext, limits)
}

func (framedSealer) DecryptObject(dek DEK, addr ObjectAddress, ciphertext []byte, limits Limits) ([]byte, error) {
	return DecryptObject(dek, addr, ciphertext, limits)
}

type compactSealer struct{}

func (compactSealer) EncryptRecord(dek DEK, addr RecordAddress, plaintext []byte, limits Limits) ([]byte, error) {
	return EncryptRecord(dek, addr, plaintext, limits)
}

func (compactSealer) DecryptRecord(dek DEK, addr RecordAddress, record []byte, limits Limits) ([]byte, error) {
	return DecryptRecord(dek, addr, record, limits)
}

func (compactSealer) NewRecordWriter(
	w io.Writer, dek DEK, addr RecordAddress, limits Limits,
) (io.WriteCloser, error) {
	return NewRecordWriter(w, dek, addr, limits)
}

func (compactSealer) NewRecordReader(
	r io.Reader, dek DEK, addr RecordAddress, limits Limits,
) (io.Reader, error) {
	return NewRecordReader(r, dek, addr, limits)
}

// NewEncryptWriter returns a WriteCloser that encrypts everything written to
// it as a framed stream to w, sealed under dek and bound to addr. The caller
// must call Close to seal the final frame; a stream that is never closed is
// never completed and cannot be decrypted.
//
// There is no plaintext ceiling here, and that is not an omission: a writer's
// input is the caller's own bytes, bounded by whatever produced them, and this
// module holds at most one frame of it. The ceiling that matters is on the way
// back in, where the length is chosen by whoever produced the ciphertext.
func NewEncryptWriter(w io.Writer, dek DEK, addr ObjectAddress) (io.WriteCloser, error) {
	return framed.NewEncryptWriter(w, dek, addr)
}

// NewDecryptReader returns a ReadCloser that decrypts a framed stream read
// from r, sealed under dek and bound to addr.
//
// maxPlaintext is the stream's total plaintext ceiling: Unlimited for no
// ceiling, or a positive byte count. Zero is refused with ErrInvalidLimit —
// unlike a Limits field, where zero means the default — because a stream has
// no defensible default size, so the choice is between refusing a zero and
// treating it as unbounded, and refusing is the one nobody arrives at by
// forgetting.
//
// The caller must check Close's error even after a successful Read: Close
// authenticates every frame the caller did not read, which is what stops a
// short read silently suppressing a later authentication failure — and which
// costs as much as decrypting the rest of the object. See framed's
// documentation for how a download path should account for that.
func NewDecryptReader(r io.Reader, dek DEK, addr ObjectAddress, maxPlaintext int64) (io.ReadCloser, error) {
	return framed.NewDecryptReader(r, dek, addr, maxPlaintext)
}

// NewDecryptRangeReader returns a Reader over the plaintext bytes
// [off, off+length) of a framed stream of total size size readable through ra.
// It decrypts one frame at a time as the caller reads, touching only the frames
// the range overlaps and holding at most one frame's plaintext in memory.
//
// size must be the object's authoritative stored ciphertext length, from the
// metadata store — never a length the object store reports at read time. Every
// check here is derived from it, so an object truncated at the storage layer
// with a size adjusted to match authenticates perfectly for any range that
// does not reach the truncated part. That is a deliberate scope limit: only a
// full sequential NewDecryptReader pass authenticates an object end to end,
// and a ranged read exists to avoid paying for that.
func NewDecryptRangeReader(
	ra io.ReaderAt, size int64, dek DEK, addr ObjectAddress, off, length int64,
) (io.Reader, error) {
	return framed.NewDecryptRangeReader(ra, size, dek, addr, off, length)
}

// EncryptObject encrypts plaintext as a whole framed stream and returns it.
//
// It is the bounded one-shot convenience over a streaming-first format, and
// limits defaults to the same 1 MiB as the compact record's — on the view that
// a caller handing over a whole object in memory has a small object, and a
// caller with a real blob should stream. Raising it is explicit.
func EncryptObject(dek DEK, addr ObjectAddress, plaintext []byte, limits Limits) ([]byte, error) {
	resolved, err := limits.ResolveFramed()
	if err != nil {
		return nil, err
	}
	if err := resolved.CheckPlaintext(int64(len(plaintext))); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if want := domain.FramedCiphertextLen(int64(len(plaintext))); want <= math.MaxInt {
		buf.Grow(int(want))
	}
	w, err := framed.NewEncryptWriter(&buf, dek, addr)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptObject decrypts a whole framed stream and returns its plaintext.
//
// The ciphertext ceiling is checked against len(ciphertext) before anything is
// allocated, and the plaintext ceiling is passed down to the reader, so a
// stream whose frames add up to more plaintext than the ceiling allows is
// refused even if its ciphertext fit. On any error it returns no plaintext at
// all rather than the prefix it managed to authenticate: a partial plaintext
// from a bounded decrypt is worse than a refusal, because the caller then
// holds something plaintext-shaped that is not the plaintext.
func DecryptObject(dek DEK, addr ObjectAddress, ciphertext []byte, limits Limits) ([]byte, error) {
	resolved, err := limits.ResolveFramed()
	if err != nil {
		return nil, err
	}
	if err := resolved.CheckCiphertext(int64(len(ciphertext))); err != nil {
		return nil, err
	}

	r, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, resolved.MaxPlaintext)
	if err != nil {
		return nil, err
	}
	out, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return out, nil
}

// EncryptRecord encrypts plaintext as one compact record bound to addr.
func EncryptRecord(dek DEK, addr RecordAddress, plaintext []byte, limits Limits) ([]byte, error) {
	resolved, err := limits.ResolveCompact()
	if err != nil {
		return nil, err
	}
	return compact.Seal(dek, addr, plaintext, resolved)
}

// DecryptRecord decrypts one compact record bound to addr. On any failure it
// returns no plaintext at all, and ErrCorrupt says nothing about which check
// failed.
func DecryptRecord(dek DEK, addr RecordAddress, record []byte, limits Limits) ([]byte, error) {
	resolved, err := limits.ResolveCompact()
	if err != nil {
		return nil, err
	}
	return compact.Open(dek, addr, record, resolved)
}

// NewRecordWriter returns a WriteCloser that seals everything written to it as
// one compact record, written to w on Close.
//
// Its cost is stated rather than discovered: a compact record has no framing,
// so there is nothing to flush incrementally and this writer holds the entire
// plaintext until Close. It bounds that memory to the configured plaintext
// ceiling and refuses the Write that would cross it, which is the only sense
// in which it is safer than a caller doing the same by hand. A caller that
// already has the bytes should call EncryptRecord.
func NewRecordWriter(w io.Writer, dek DEK, addr RecordAddress, limits Limits) (io.WriteCloser, error) {
	resolved, err := limits.ResolveCompact()
	if err != nil {
		return nil, err
	}
	return compact.NewWriter(w, dek, addr, resolved)
}

// NewRecordReader returns a Reader over the plaintext of the single compact
// record in r.
//
// It is the fail-closed entry point. If either ceiling is in force, r's length
// must be establishable without reading it — a Len method, a Stat plus Seek on
// a regular file, or a Seek to the end — and an r that cannot say is refused
// with ErrUnknownLength rather than read until the ceiling is hit. A caller whose source genuinely
// cannot declare its length has two honest options and no third: read it
// itself and call DecryptRecord with the bytes it actually got, or pass
// Unlimited and have said so.
//
// The record is read and authenticated here rather than lazily on first Read:
// one tag covers the whole value, so there is nothing to be lazy about, and a
// caller cannot be handed a Reader that is going to fail. The declared length
// must cover exactly one record; trailing bytes are refused with ErrCorrupt,
// and the reader may perform one extra read to establish EOF.
func NewRecordReader(r io.Reader, dek DEK, addr RecordAddress, limits Limits) (io.Reader, error) {
	resolved, err := limits.ResolveCompact()
	if err != nil {
		return nil, err
	}
	return compact.NewReader(r, dek, addr, resolved)
}
