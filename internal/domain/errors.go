// Package domain is the single home for every value object seal names: the
// addresses a ciphertext is bound to, the size ceilings every one-shot entry
// point carries, the format version registry both wire shapes share, and the
// error taxonomy. Nothing here performs I/O, derives a key, or touches a
// cipher; the two formats live in internal/framed and internal/compact, and
// the facade re-exports what a consumer must name.
//
// Two invariants live here rather than in the format packages, because a
// format package that has to remember them will eventually forget:
//
//  1. An address is canonical or it does not exist. Both address types are
//     structs with unexported fields, reachable only through a validating
//     constructor, because the address is bound into every AEAD tag — a value
//     that reached the additional authenticated data without being canonical
//     would produce ciphertext no later process can re-derive the binding for.
//  2. A size ceiling resolves once, in one place, and a zero never means
//     "unbounded". See Limits.
package domain

import (
	"errors"
	"fmt"
)

// ErrCorrupt is returned whenever decryption detects that the ciphertext does
// not authenticate: a flipped bit, a dropped or reordered frame, a truncated
// stream, a tampered header, a record relocated to another address, or an
// address that does not match what the ciphertext was sealed under. It never
// carries any detail about which, so it is safe to return verbatim to a
// caller without risking a leak of key material or plaintext — and because
// naming the failing check would hand an attacker a dimension to search
// along (CONVENTIONS.md, "Errors from a security path").
var ErrCorrupt = errors.New("seal: corrupt ciphertext")

// ErrInvalidDEK is returned when a caller supplies a DEK that holds no usable
// key material: the zero value, one already destroyed, or one whose shared
// backing array was zeroized through another copy.
//
// keyring.DEK makes the length cases unconstructible — DEKFrom validates and
// the material is unexported — so this check is narrower than the one the
// extracted code needed, where the DEK was a bare []byte and a nil or short
// secret still derived a usable-looking key from HKDF with no error of its
// own. What remains is the case the type cannot catch: a DEK used after
// Destroy, whose all-zero material would otherwise seal real data under a key
// an attacker can guess.
var ErrInvalidDEK = errors.New("seal: dek holds no usable key material")

// ErrInvalidAddress is returned by the address constructors when a component
// is not safe to bind into additional authenticated data and into whatever
// database key, log field or object name the same value reaches.
var ErrInvalidAddress = errors.New("seal: invalid address")

// ErrRange is returned by a ranged read when the requested [off, off+length)
// is negative or falls outside the object's plaintext size. It is distinct
// from ErrCorrupt because it reports a caller usage error — a bad byte range
// — rather than a ciphertext authentication failure, so a caller such as an
// HTTP range handler can tell "respond 416" apart from "respond 500" without
// matching on error text.
var ErrRange = errors.New("seal: invalid byte range")

// ErrClosed is returned by a write after Close has already sealed the stream's
// final frame or the record's single tag: the ciphertext is complete and
// cannot be extended.
var ErrClosed = errors.New("seal: write to a closed writer")

// ErrInvalidFrameSize is returned when a frame size outside
// [MinFrameSize, MaxFrameSize] is supplied to the framed format's internal
// constructor. Reachable only through that package's test-only seam today,
// since the production constructor always passes the fixed FrameSize
// constant.
var ErrInvalidFrameSize = errors.New("seal: frame size out of range")

// ErrLimitExceeded reports that a one-shot entry point refused because the
// input exceeded a configured size ceiling. Every error that matches it is a
// *LimitError, which names the ceiling and both numbers; match the sentinel
// with errors.Is and reach for the detail with errors.As.
//
// A refusal, never a truncated or partial result: a bounded decrypt that
// returned the first MaxCiphertext bytes' worth of plaintext would be worse
// than a refusal, because the caller would have something plaintext-shaped
// that is not the plaintext.
var ErrLimitExceeded = errors.New("seal: size limit exceeded")

// ErrUnknownLength reports that a ceiling is configured and the input's length
// could not be established before reading it.
//
// This is the fail-closed half of the ceiling discipline and it is deliberately
// the same rule as CAS §9.2's MaxContentLength caveat, which fails closed on an
// unknown length: a chunked upload with no declared size is refused when a
// limit caveat exists. Discovering the length by reading until the ceiling is
// hit would be the allocation-bomb pattern with extra steps — the ceiling
// exists so that nothing is read or allocated on an attacker's word.
var ErrUnknownLength = errors.New("seal: input length cannot be established before reading")

// ErrInvalidLimit reports a ceiling that is neither Unlimited, nor zero
// (meaning the entry point's default), nor a positive byte count.
var ErrInvalidLimit = errors.New("seal: invalid size limit")

// LimitError is the typed error a size ceiling produces. It names which
// ceiling was exceeded and reports both the ceiling and the actual length,
// because a refusal a caller cannot size its retry against is a refusal it
// will work around by removing the ceiling.
//
// Reporting a length here does not breach CONVENTIONS.md's rule against
// printing a secret's length: these are the lengths of a *ciphertext* a
// caller handed us or of a plaintext the caller already holds, which is a
// record about material rather than material. Nothing here is derived from
// the key or from the plaintext's content.
type LimitError struct {
	// Limit names the ceiling in the words its field uses, so the message
	// says which of the two configured numbers to change.
	Limit string
	// Max is the ceiling in bytes, as resolved.
	Max int64
	// Actual is the length that exceeded it, in bytes. It is -1 when the
	// length is known only to be greater than Max.
	Actual int64
}

func (e *LimitError) Error() string {
	if e.Actual < 0 {
		return fmt.Sprintf("seal: %s exceeded: more than %d bytes", e.Limit, e.Max)
	}
	return fmt.Sprintf("seal: %s exceeded: %d bytes, limit %d", e.Limit, e.Actual, e.Max)
}

// Unwrap returns ErrLimitExceeded so errors.Is(err, ErrLimitExceeded) holds
// for every ceiling refusal, whichever ceiling it was.
func (e *LimitError) Unwrap() error { return ErrLimitExceeded }
