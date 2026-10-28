// Package compact implements format version 2: the compact record for small
// whole values. It is the one genuinely new thing in this module; everything
// else is an extraction.
//
// # Why it exists
//
// The framed format's 25-byte header plus a 16-byte tag per frame is 0.004%
// overhead on a 1 MiB blob and over 200% on a 20-byte fact literal, and kgs
// encrypts per attribute — potentially tens of millions of short values. So
// this format drops the framing, derives its nonce rather than storing it, and
// binds its additional authenticated data to the value's address. A record is
// 33 bytes over its plaintext against the framed format's 41, which is a
// modest win on size; the real win is that it costs one AEAD operation and no
// framing state, and that the thing it binds to is an arbitrary address rather
// than a (tenant, object) pair.
//
// # The binding is the point, not an optimisation
//
// Generalised from the framed format's object binding, a kgs attribute value
// binds to (graph, fact id, attribute). Without that, an encrypted salary
// value can be relocated onto another row — by a bug, or by anyone with
// database write access — and will decrypt cleanly to the wrong answer. With
// it, relocation is a decryption failure. This is leak channel #17 in the kgs
// design, and it is the reason this module is a module.
//
// # Nonce management at scale, reasoned about rather than assumed
//
// A single DEK encrypting ten million small records is well inside the
// territory where random 96-bit nonces need an argument rather than a
// citation. So this format does what keyring's local adapter already does for
// the analogous problem: it derives a per-record key from a per-record salt,
// and derives the nonce from the same expansion. A (key, nonce) pair repeats
// only if two records draw the same 128-bit salt, which moves the bound from
// the 96-bit nonce space into the 128-bit salt space.
//
// At a 2^-32 risk target that is about 2^48.5 records — roughly 4.0 x 10^14 —
// per DEK, against about 2^32.5, roughly 6.1 x 10^9, for a single key with
// random 96-bit nonces: 65,536 times more records for the same risk. It is not
// "uncapped", and docs/format.md writes out the arithmetic rather than leaving
// the claim to be trusted.
//
// The derived nonce could equally be all-zero bytes, since the key is already
// unique per record. Deriving it from the same expansion costs nothing, stores
// nothing, and keeps the construction sound if the key derivation is ever
// changed to be shared across records — which is exactly the change someone
// makes for performance without re-reading this comment.
package compact

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/domain"
)

// derivedLen is the single HKDF expansion's output: an AES-256 key followed by
// the record's GCM nonce.
const derivedLen = domain.DEKSize + domain.NonceSize

// deriveRecordKey derives the per-record key and nonce from dek and the
// record's salt. See the package doc comment for why both come from one
// expansion and why the nonce is derived rather than stored.
func deriveRecordKey(dek keyring.DEK, salt []byte) (key, nonce []byte, err error) {
	if err := dek.Validate(); err != nil {
		return nil, nil, domain.ErrInvalidDEK
	}
	okm, err := hkdf.Key(sha256.New, dek.Bytes(), salt, domain.CompactKeyInfo, derivedLen)
	if err != nil {
		return nil, nil, fmt.Errorf("seal: derive record key: %w", err)
	}
	return okm[:domain.DEKSize], okm[domain.DEKSize:], nil
}

// newAEAD builds the AES-256-GCM AEAD for one record.
func newAEAD(dek keyring.DEK, salt []byte) (aead cipher.AEAD, nonce []byte, err error) {
	key, nonce, err := deriveRecordKey(dek, salt)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("seal: new AES cipher: %w", err)
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, nonce, nil
}

// recordAAD builds a record's additional authenticated data: the record's
// entire 17-byte unencrypted prefix — the format version byte and the salt,
// exactly as written or read — followed by the address.
//
// Binding the whole prefix rather than picking out the version byte is the
// framed format's rule applied again: all of it is covered, uniformly, so
// there is no "which prefix bytes are authenticated" question for the next
// reader. The salt is already bound through the key derivation, so including
// it here is belt and braces; the version byte is bound here and nowhere else,
// which is what makes a version-2 record impossible to open as a future
// version 4 even if the two layouts were otherwise compatible. That is what a
// shared magic prefix across the two formats would have bought, bought without
// spending bytes on every record.
func recordAAD(prefix []byte, addr domain.RecordAddress) []byte {
	out := make([]byte, 0, len(prefix)+8+len(addr.String()))
	out = append(out, prefix...)
	return addr.AppendAAD(out)
}

// Seal encrypts plaintext as one compact record bound to addr, under dek.
//
// limits bounds the plaintext before anything is allocated, which is the
// encrypt side of the ceiling discipline: it bounds what a caller may hand us.
// A plaintext over the ceiling is refused with a *domain.LimitError naming it,
// and no partial record is produced.
func Seal(
	dek keyring.DEK, addr domain.RecordAddress, plaintext []byte, limits domain.Resolved,
) ([]byte, error) {
	salt := make([]byte, domain.CompactSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("seal: generate record salt: %w", err)
	}
	return sealWithSalt(dek, addr, plaintext, salt, limits)
}

// sealWithSalt is Seal with the salt supplied, so vector generation is
// deterministic. It is reachable from outside this package only through
// export_test.go: a caller-chosen salt is a caller-chosen key, and reusing one
// across two records is the one way to make this format unsafe.
func sealWithSalt(
	dek keyring.DEK, addr domain.RecordAddress, plaintext []byte, salt []byte, limits domain.Resolved,
) ([]byte, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}
	// Checked before the output buffer is sized, not after.
	if err := limits.CheckPlaintext(int64(len(plaintext))); err != nil {
		return nil, err
	}
	if len(salt) != domain.CompactSaltSize {
		return nil, fmt.Errorf("seal: record salt is %d bytes, want %d", len(salt), domain.CompactSaltSize)
	}

	aead, nonce, err := newAEAD(dek, salt)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, domain.CompactOverhead+len(plaintext))
	out = append(out, byte(domain.VersionCompact))
	out = append(out, salt...)
	return aead.Seal(out, nonce, plaintext, recordAAD(out, addr)), nil
}

// Open decrypts one compact record bound to addr, under dek.
//
// limits bounds the record before anything is allocated, and this is the
// ceiling that matters: on this side the length was chosen by whoever produced
// the bytes. A record over the ceiling is refused with a *domain.LimitError
// naming it, and no plaintext — not even a prefix of it — is returned.
//
// Every other failure is domain.ErrCorrupt and says nothing about which: a
// flipped bit, a record relocated to another address, a record sealed under
// another DEK, a truncated record, and an unrecognised format version byte are
// deliberately indistinguishable. Naming them apart would tell an attacker
// which of their edits the decoder got furthest past.
func Open(
	dek keyring.DEK, addr domain.RecordAddress, record []byte, limits domain.Resolved,
) ([]byte, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}
	if err := limits.CheckCiphertext(int64(len(record))); err != nil {
		return nil, err
	}
	if len(record) < domain.CompactOverhead {
		return nil, domain.ErrCorrupt
	}
	// And the plaintext ceiling, against the length the record declares by
	// being as long as it is. The ciphertext ceiling is the one that matters,
	// and by default it is derived from this one so the two agree — but a
	// caller that set MaxCiphertext to Unlimited explicitly while leaving
	// MaxPlaintext in place has said something specific, and reading that as
	// "no bound on either" would be the surprising answer rather than the
	// safe one. Both ceilings are enforced, each on the thing it names.
	if err := limits.CheckPlaintext(int64(len(record) - domain.CompactOverhead)); err != nil {
		return nil, err
	}
	if record[0] != byte(domain.VersionCompact) {
		return nil, domain.ErrCorrupt
	}

	prefix := record[:domain.CompactPrefixSize]
	aead, nonce, err := newAEAD(dek, prefix[1:])
	if err != nil {
		return nil, err
	}

	body := record[domain.CompactPrefixSize:]
	plaintext, err := aead.Open(nil, nonce, body, recordAAD(prefix, addr))
	if err != nil {
		return nil, domain.ErrCorrupt
	}
	return plaintext, nil
}

// writer buffers a whole value and seals it as one record on Close.
//
// It exists because CHARTER.md offers both API shapes over the compact format,
// and the cost has to be stated rather than discovered: a compact record has
// no framing, so there is nothing to flush incrementally and this writer holds
// the entire plaintext in memory until Close. It bounds that memory to the
// configured plaintext ceiling and refuses the moment a Write would exceed it,
// which is the only sense in which it is safer than the caller doing the same
// thing by hand. A caller that already has the bytes should call Seal; this is
// for a caller holding an io.Reader it would otherwise have to drain itself.
type writer struct {
	w      io.Writer
	dek    keyring.DEK
	addr   domain.RecordAddress
	limits domain.Resolved
	buf    []byte
	err    error
	closed bool
}

// NewWriter returns a WriteCloser that seals everything written to it as one
// compact record, written to w on Close. See writer's doc comment for what it
// costs: the whole value is buffered.
func NewWriter(
	w io.Writer, dek keyring.DEK, addr domain.RecordAddress, limits domain.Resolved,
) (io.WriteCloser, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}
	if err := dek.Validate(); err != nil {
		return nil, domain.ErrInvalidDEK
	}
	return &writer{w: w, dek: dek, addr: addr, limits: limits}, nil
}

func (x *writer) Write(p []byte) (int, error) {
	if x.err != nil {
		return 0, x.err
	}
	if x.closed {
		return 0, domain.ErrClosed
	}
	// Checked before append grows the buffer, so a caller streaming an
	// unbounded source can never make this writer allocate past its ceiling.
	if err := x.limits.CheckPlaintext(int64(len(x.buf)) + int64(len(p))); err != nil {
		x.err = err
		return 0, err
	}
	x.buf = append(x.buf, p...)
	return len(p), nil
}

func (x *writer) Close() error {
	if x.closed {
		return x.err
	}
	x.closed = true
	if x.err != nil {
		return x.err
	}
	record, err := Seal(x.dek, x.addr, x.buf, x.limits)
	if err != nil {
		x.err = err
		return err
	}
	if _, err := x.w.Write(record); err != nil {
		x.err = fmt.Errorf("seal: write record: %w", err)
		return x.err
	}
	return nil
}

// The four renderings. A compact writer holds the whole plaintext, which
// CONVENTIONS.md covers as material under a different name, and a DEK whose
// own redaction does not reach it through this type's unexported field.
func (x *writer) String() string             { return domain.RedactedAs("seal.CompactWriter") }
func (x *writer) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, x.String()) }
func (x *writer) MarshalJSON() ([]byte, error) {
	return []byte(`"` + domain.RedactedAs("seal.CompactWriter") + `"`), nil
}
func (x *writer) LogValue() slog.Value { return slog.StringValue(x.String()) }

// reader hands back the plaintext of one compact record.
//
// It holds the whole plaintext, because a compact record cannot be
// authenticated in pieces: there is one tag over the whole value, and
// returning bytes before checking it would be returning unauthenticated
// plaintext. So this type is a buffer with a redacting rendering, and it
// exists for the same reason writer does.
type reader struct {
	plain []byte
	off   int
}

// NewReader returns a Reader over the plaintext of the single compact record
// in r, bound to addr and sealed under dek.
//
// It is the fail-closed entry point. If either ceiling is in force, r's length
// must be establishable without reading it — a Len method, a Stat, or a Seek
// to the end — and an r that cannot say is refused with
// domain.ErrUnknownLength. That is deliberately the same rule as CAS §9.2's
// MaxContentLength caveat: a chunked upload with no declared size is refused
// when a limit caveat exists. Discovering the length by reading until the
// ceiling is hit would be the allocation-bomb pattern with extra steps.
//
// A caller whose source genuinely cannot declare its length has two honest
// options, and no third: read it itself and call Open with the bytes it
// actually got, or pass domain.Unlimited and have said so.
//
// The record is read and authenticated here, at construction, not lazily on
// first Read. There is nothing to be lazy about — one tag covers the whole
// value — and surfacing the failure from the constructor means a caller cannot
// hold a Reader that is going to fail.
func NewReader(
	r io.Reader, dek keyring.DEK, addr domain.RecordAddress, limits domain.Resolved,
) (io.Reader, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}

	var declared int64 = -1
	if limits.Bounded() {
		n, ok := domain.DerivableLength(r)
		if !ok || n < 0 {
			return nil, fmt.Errorf("%w: a size ceiling is configured, so %T must declare a non-negative length",
				domain.ErrUnknownLength, r)
		}
		if err := limits.CheckCiphertext(n); err != nil {
			return nil, err
		}
		// The ciphertext length declares the plaintext length for a compact
		// record. Check both ceilings before allocating for the read; a caller
		// that opted out of MaxCiphertext must not thereby lose MaxPlaintext.
		if n >= domain.CompactOverhead {
			if err := limits.CheckPlaintext(n - domain.CompactOverhead); err != nil {
				return nil, err
			}
		}
		declared = n
	}

	record, err := readAll(r, declared)
	if err != nil {
		return nil, err
	}
	plain, err := Open(dek, addr, record, limits)
	if err != nil {
		return nil, err
	}
	return &reader{plain: plain}, nil
}

// readAll reads r to EOF, pre-sizing the buffer from declared when a length
// was established and refusing anything beyond it.
func readAll(r io.Reader, declared int64) ([]byte, error) {
	if declared < 0 {
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("seal: read record: %w", err)
		}
		return b, nil
	}
	buf := make([]byte, declared)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("seal: read record: %w", err)
	}
	// A declared length is a claim about one record, not a prefix size. If
	// more bytes follow, the declared record is not the whole input; accepting
	// it would authenticate a prefix and silently ignore the rest.
	extra, err := io.ReadAll(io.LimitReader(r, 1))
	if err != nil {
		return nil, fmt.Errorf("seal: read record: %w", err)
	}
	if len(extra) != 0 {
		return nil, domain.ErrCorrupt
	}
	return buf, nil
}

func (x *reader) Read(p []byte) (int, error) {
	if x.off >= len(x.plain) {
		return 0, io.EOF
	}
	n := copy(p, x.plain[x.off:])
	x.off += n
	return n, nil
}

// The four renderings; see writer's. This type holds plaintext, which is why
// a bare *bytes.Reader would not do: %s of one prints the value.
func (x *reader) String() string             { return domain.RedactedAs("seal.CompactReader") }
func (x *reader) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, x.String()) }
func (x *reader) MarshalJSON() ([]byte, error) {
	return []byte(`"` + domain.RedactedAs("seal.CompactReader") + `"`), nil
}
func (x *reader) LogValue() slog.Value { return slog.StringValue(x.String()) }

// Overhead returns the number of bytes a record of n plaintext bytes occupies.
// It exists so a caller sizing a column, or deriving a ciphertext ceiling from
// a plaintext one, does not have to add up the layout itself.
func Overhead(n int64) int64 { return n + domain.CompactOverhead }
