package domain

// This file is the size-ceiling discipline, and every rule in it is a
// security control rather than a courtesy. CHARTER.md states five; this is
// where they are implemented, and each one is named at the code that enforces
// it.
//
//  1. Two separate limits, not one. MaxPlaintext bounds what a caller may
//     hand us on the encrypt side. MaxCiphertext bounds the decrypt side, and
//     it is the one that matters, because an attacker controls the
//     ciphertext's length.
//  2. Checked before allocation, from the declared or derivable length —
//     never by reading and discovering. This is the allocation-bomb pattern,
//     and it is kept distinct from the framed format's frame_size bound,
//     which exists purely to bound decoder resource use and authenticates
//     nothing. Two mechanisms.
//  3. Fail closed on an unknown length. If a ceiling is configured and the
//     input length cannot be established up front, the operation is refused
//     with ErrUnknownLength. See DerivableLength.
//  4. A typed error naming the limit, never a truncated or partial result.
//     See LimitError.
//  5. Streaming is not exempt. A caller streaming into a buffer has exactly
//     the same exposure, so the framed reader takes a total plaintext
//     ceiling. Streaming bounds *our* memory to one frame; it does not bound
//     the caller's.

import (
	"fmt"
	"io"
	"io/fs"
	"math"
)

// Unlimited disables a ceiling. It must be written out, because a zero field
// means "this entry point's default" and an accidental zero — a Limits value
// someone built with a struct literal and did not finish filling in — must
// never disable a security control. A deployment that runs without a ceiling
// has said so.
const Unlimited int64 = -1

// DefaultMaxPlaintext is the plaintext ceiling a one-shot entry point applies
// when none is configured: 1 MiB.
//
// It is chosen so a compact record never exceeds what a single framed frame
// would hold (FrameSize is also 1 MiB), which keeps one invariant across both
// formats and makes the choice between them a question about ranged reads
// rather than about size. CHARTER.md marks the number open to revision; the
// reasoning is the part worth keeping.
//
// Raising it is explicit, per-call, and cheap. Lowering it is also worth
// doing: a deployment that knows its fact literals are under a kilobyte
// should say a kilobyte.
const DefaultMaxPlaintext int64 = 1 << 20

// Limits is the pair of ceilings a one-shot entry point carries.
//
// A zero field means "this entry point's default" rather than "unbounded",
// which is the one decision in this type that has to be right: the zero value
// of a struct is what a caller gets when they forget, and forgetting must not
// turn a bounded decrypt into an unbounded one.
type Limits struct {
	// MaxPlaintext bounds the plaintext a seal operation will accept, in
	// bytes. Zero means DefaultMaxPlaintext; Unlimited disables it.
	MaxPlaintext int64
	// MaxCiphertext bounds the ciphertext an open operation will accept, in
	// bytes. Zero means MaxPlaintext plus the format's overhead, so a caller
	// that raises one ceiling is not left unable to read back what it just
	// wrote; Unlimited disables it.
	//
	// It is a separate field and not a derived number because the two bound
	// different things on different sides of the trust boundary. The derived
	// default is a convenience for the common case where they should agree;
	// a caller that stores ciphertext from a source it does not control
	// should set this one directly and leave MaxPlaintext generous.
	MaxCiphertext int64
}

// Resolved is a Limits with every zero filled in and every value checked,
// which is the only form the format packages see. Resolving once, at the
// boundary, is what keeps the defaults from being re-decided in four places.
type Resolved struct {
	MaxPlaintext  int64
	MaxCiphertext int64
}

// Resolve fills in l's defaults for a format whose ciphertext costs overhead
// bytes more than its plaintext, and rejects a nonsensical ceiling with
// ErrInvalidLimit.
//
// The ciphertext default is derived with an overflow guard rather than a bare
// addition: MaxPlaintext is a caller-supplied int64, and a caller that passes
// math.MaxInt64 meaning "effectively unlimited" would otherwise wrap the
// derived ciphertext ceiling negative and disable the check it was asking to
// keep.
func (l Limits) Resolve(overhead int64) (Resolved, error) {
	plaintext, err := resolveOne("max plaintext", l.MaxPlaintext, DefaultMaxPlaintext)
	if err != nil {
		return Resolved{}, err
	}

	derived := Unlimited
	if plaintext != Unlimited {
		derived = plaintext
		if derived <= math.MaxInt64-overhead {
			derived += overhead
		} else {
			derived = math.MaxInt64
		}
	}
	ciphertext, err := resolveOne("max ciphertext", l.MaxCiphertext, derived)
	if err != nil {
		return Resolved{}, err
	}

	return Resolved{MaxPlaintext: plaintext, MaxCiphertext: ciphertext}, nil
}

// resolveOne turns one configured ceiling into its effective value: zero
// becomes def, Unlimited stays, a positive value stays, and anything else is
// ErrInvalidLimit.
func resolveOne(name string, configured, def int64) (int64, error) {
	switch {
	case configured == 0:
		return def, nil
	case configured == Unlimited:
		return Unlimited, nil
	case configured > 0:
		return configured, nil
	default:
		return 0, fmt.Errorf("%w: %s is %d; use a positive byte count, zero for the default, or Unlimited",
			ErrInvalidLimit, name, configured)
	}
}

// CheckPlaintext reports whether n bytes of plaintext are within the resolved
// ceiling, returning a *LimitError that names it if not. Rule 1's encrypt
// side: it bounds what a caller may hand us.
func (r Resolved) CheckPlaintext(n int64) error {
	if r.MaxPlaintext != Unlimited && n > r.MaxPlaintext {
		return &LimitError{Limit: "max plaintext", Max: r.MaxPlaintext, Actual: n}
	}
	return nil
}

// CheckCiphertext reports whether n bytes of ciphertext are within the
// resolved ceiling, returning a *LimitError that names it if not.
//
// Rule 1's decrypt side, and the one that matters: on this side the length is
// chosen by whoever produced the bytes, so this is the check that stands
// between a stored row and an allocation sized by an attacker. Rule 2 is why
// it is called with a declared length before anything is allocated, rather
// than after a read discovers how much there was.
func (r Resolved) CheckCiphertext(n int64) error {
	if r.MaxCiphertext != Unlimited && n > r.MaxCiphertext {
		return &LimitError{Limit: "max ciphertext", Max: r.MaxCiphertext, Actual: n}
	}
	return nil
}

// Bounded reports whether either ceiling is in force. When neither is, rule
// 3's fail-closed refusal does not apply: there is nothing an unknown length
// could exceed.
func (r Resolved) Bounded() bool {
	return r.MaxPlaintext != Unlimited || r.MaxCiphertext != Unlimited
}

// ValidateStreamCeiling checks a total-plaintext ceiling handed to a
// streaming reader: Unlimited, or a positive byte count.
//
// Zero is refused here, where Limits treats it as "the default", and the
// asymmetry is deliberate. A whole-value one-shot has a defensible default —
// a value that does not fit in 1 MiB is not a compact record — while a stream
// has none: the framed format exists for objects whose size is not known in
// advance, so any number this package picked would be wrong for somebody.
// With no default to fall back on, the choice is between refusing a zero and
// treating it as unbounded, and refusing is the one that cannot be arrived at
// by forgetting.
func ValidateStreamCeiling(maxPlaintext int64) error {
	if maxPlaintext == Unlimited || maxPlaintext > 0 {
		return nil
	}
	return fmt.Errorf("%w: stream plaintext ceiling is %d; pass Unlimited to stream without one, explicitly",
		ErrInvalidLimit, maxPlaintext)
}

// DerivableLength reports r's remaining length without reading it, and
// whether it could be established at all. It is rule 3's mechanism.
//
// Three shapes answer, in order of cost: a Len method (what *bytes.Reader,
// *bytes.Buffer and *strings.Reader have), a Stat (an *os.File), and a
// Seeker (anything that can report its own end). Everything else — a network
// connection, an HTTP body, a pipe, an io.LimitedReader over any of them —
// cannot say, and a ceiling-bearing entry point refuses it with
// ErrUnknownLength rather than reading until the ceiling is hit.
//
// The Seeker path restores the original offset before returning, so a
// successful probe leaves the reader exactly where it was found.
func DerivableLength(r io.Reader) (int64, bool) {
	if l, ok := r.(interface{ Len() int }); ok {
		n := l.Len()
		if n < 0 {
			return 0, false
		}
		return int64(n), true
	}
	if st, ok := r.(interface {
		Stat() (fs.FileInfo, error)
	}); ok {
		if info, err := st.Stat(); err == nil && info.Mode().IsRegular() {
			if s, isSeeker := r.(io.Seeker); isSeeker {
				if cur, seekErr := s.Seek(0, io.SeekCurrent); seekErr == nil {
					return info.Size() - cur, true
				}
			}
			return info.Size(), true
		}
	}
	if s, ok := r.(io.Seeker); ok {
		cur, err := s.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, false
		}
		end, err := s.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, false
		}
		if _, err := s.Seek(cur, io.SeekStart); err != nil {
			return 0, false
		}
		return end - cur, true
	}
	return 0, false
}
