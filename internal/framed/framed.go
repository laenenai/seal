// Package framed implements format version 1: the framed streaming AEAD,
// extracted from cas/internal/crypto rather than designed here. See
// docs/format.md for the committed wire format this file implements, and
// testdata/vectors.json for the ciphertext that pins it.
//
// It is an extraction and not a rewrite, because each of its properties is a
// bug someone already found: truncation detection, reorder detection, bit-flip
// detection anywhere including the header, a frame_size bound that
// authenticates nothing and exists only to bound decoder resource use, ranged
// reads that touch only the frames they need, and additional authenticated
// data that binds ciphertext to exactly one object of exactly one tenant. The
// tests in framed_test.go are CAS's, under their own names, for the same
// reason.
//
// What is new here and was not in the extracted code:
//
//   - The DEK arrives as a keyring.DEK rather than a []byte, so the length
//     check the original needed is now unconstructible and only the
//     destroyed-key case remains. See domain.ErrInvalidDEK.
//   - The reader takes a total plaintext ceiling (CHARTER.md's fifth ceiling
//     rule). Streaming bounds this package's memory to one frame; it does not
//     bound the caller's.
//   - The three returned types redact themselves. They hold a cipher.AEAD,
//     whose expanded AES key schedule is reachable by reflection through the
//     unexported fields of a value fmt was handed as an io.ReadCloser — so
//     without the four interfaces, fmt.Sprintf("%+v", reader) prints round
//     keys derived from the caller's DEK. The extracted code had this hole;
//     CONVENTIONS.md's rule that redaction is not inherited through an
//     unexported field is what found it.
package framed

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/domain"
)

// deriveFrameKey derives the single per-stream frame key from dek and the
// stream's random salt via HKDF-SHA256.
//
// The random per-stream salt means the same dek reused across two streams
// (which should not happen — every object gets its own DEK — but costs
// nothing to defend against) still derives unrelated frame keys. It is also
// what moves the bound on how many streams one DEK may seal from the nonce
// space into the salt space; the arithmetic is in docs/format.md.
func deriveFrameKey(dek keyring.DEK, salt []byte) ([]byte, error) {
	if err := dek.Validate(); err != nil {
		return nil, domain.ErrInvalidDEK
	}
	key, err := hkdf.Key(sha256.New, dek.Bytes(), salt, domain.FramedKeyInfo, domain.DEKSize)
	if err != nil {
		return nil, fmt.Errorf("seal: derive frame key: %w", err)
	}
	return key, nil
}

// newAEAD derives the per-stream frame key and builds the AES-256-GCM AEAD
// used to seal and open every frame in the stream.
func newAEAD(dek keyring.DEK, salt []byte) (cipher.AEAD, error) {
	key, err := deriveFrameKey(dek, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal: new AES cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// frameNonce deterministically derives frame index's GCM nonce: the index as a
// big-endian 96-bit integer. This is safe because the frame key is unique per
// stream (it depends on the stream's random salt), and the index never repeats
// within a stream, so no (key, nonce) pair is ever reused.
func frameNonce(index uint64) []byte {
	nonce := make([]byte, domain.NonceSize)
	binary.BigEndian.PutUint64(nonce[domain.NonceSize-8:], index)
	return nonce
}

// frameAAD builds the additional authenticated data for one frame: the
// stream's entire 25-byte header (magic, frame size, and salt, exactly as
// written or read — not just one field of it), the address (tenant and object,
// each length-prefixed so the encoding is unambiguous), the frame index, and
// the final-frame flag.
//
// Binding the whole header, not just the fields a naive reading might think
// matter, means there is no "which header fields are covered" question for the
// next reader: all of them are, uniformly, because every frame's GCM tag
// depends on it. Tampering with any header byte — magic, frame size, or salt —
// changes every frame's AAD from what the stream was actually sealed under, so
// every frame fails to authenticate. This is also what closes a gap a
// frame-size-only check could not: the header's frame_size field alone,
// checked only for being in range, is still malleable to any other in-range
// value on a single-frame object (the short-final-frame path doesn't care what
// frame_size claims, since the whole remaining ciphertext is read regardless)
// — binding the header into the AAD means any such change is caught directly,
// the same way a tampered salt always was.
//
// The frame index is what makes a dropped or reordered frame detectable; the
// final flag is what makes a truncated stream detectable, since a stream cut
// short after a non-final frame can only be completed by a frame whose AAD
// says final=false, which never authenticates against a final=true guess.
func frameAAD(header []byte, addr domain.ObjectAddress, index uint64, final bool) []byte {
	out := make([]byte, 0, len(header)+8+len(addr.Tenant())+len(addr.Object())+9)
	out = append(out, header...)
	out = addr.AppendAAD(out)
	out = binary.BigEndian.AppendUint64(out, index)
	if final {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

// newHeader builds the stream header (magic, frame size, and salt) for a
// stream using the given frameSize, rejecting one outside
// [MinFrameSize, MaxFrameSize] with domain.ErrInvalidFrameSize.
func newHeader(frameSize int, salt []byte) ([]byte, error) {
	if frameSize < domain.MinFrameSize || frameSize > domain.MaxFrameSize {
		return nil, fmt.Errorf("%w: %d not in [%d,%d]",
			domain.ErrInvalidFrameSize, frameSize, domain.MinFrameSize, domain.MaxFrameSize)
	}
	header := make([]byte, 0, domain.FramedHeaderSize)
	header = append(header, domain.FramedMagic...)
	header = binary.BigEndian.AppendUint32(header, uint32(frameSize)) //nolint:gosec // bounds-checked above
	header = append(header, salt...)
	return header, nil
}

// parseHeader validates a header buffer's magic and frame size and returns the
// stream's frame size and salt. buf must be exactly domain.FramedHeaderSize
// bytes.
//
// frame_size is validated against [MinFrameSize, MaxFrameSize] here purely to
// bound decoder resource use (an out-of-range value is rejected before any
// frame is touched, so a hostile header can't force an enormous number of
// vanishingly small frames or an oversized frame buffer) — this check alone
// does not authenticate the field. What actually makes the header effectively
// authenticated is that frameAAD binds the entire header (including frame_size
// and salt) into every frame's AAD: any in-range tampering still changes the
// AAD from what the stream was sealed under, which fails every frame's GCM
// tag. Two mechanisms, and the format document keeps them apart.
func parseHeader(buf []byte) (frameSize uint32, salt []byte, err error) {
	if len(buf) != domain.FramedHeaderSize {
		return 0, nil, domain.ErrCorrupt
	}
	if string(buf[:len(domain.FramedMagic)]) != domain.FramedMagic {
		return 0, nil, domain.ErrCorrupt
	}
	frameSize = binary.BigEndian.Uint32(buf[len(domain.FramedMagic) : len(domain.FramedMagic)+4])
	if frameSize < domain.MinFrameSize || frameSize > domain.MaxFrameSize {
		return 0, nil, domain.ErrCorrupt
	}
	salt = buf[len(domain.FramedMagic)+4:]
	return frameSize, salt, nil
}

// encryptWriter implements io.WriteCloser, buffering plaintext into frameSize
// chunks (always FrameSize in production; a smaller size is only ever used by
// tests) and sealing each as a frame. A full buffer is only flushed as a
// non-final frame once more data is known to follow; whatever remains (0 to
// frameSize bytes, including a full buffer that never got a chance to prove it
// wasn't last) is sealed as the final frame on Close, so every stream ends in
// exactly one frame whose AAD says final=true.
type encryptWriter struct {
	w         io.Writer
	aead      cipher.AEAD
	addr      domain.ObjectAddress
	header    []byte // the exact bytes written for the stream header, bound into every frame's AAD
	index     uint64
	frameSize int
	buf       []byte // pending plaintext, 0..frameSize bytes, not yet sealed
	err       error
	closed    bool
}

// newEncryptWriter is the stream's internal constructor: it draws the salt
// from randSource and uses the caller's frameSize. It exists so that committed
// test fixtures do not have to be megabytes large to exercise multiple frames,
// and so vector generation is deterministic. It is reachable from outside this
// package only through export_test.go; production code goes through
// NewEncryptWriter, which always passes crypto/rand and FrameSize.
func newEncryptWriter(
	w io.Writer, dek keyring.DEK, addr domain.ObjectAddress, randSource io.Reader, frameSize int,
) (io.WriteCloser, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}
	salt := make([]byte, domain.FramedSaltSize)
	if _, err := io.ReadFull(randSource, salt); err != nil {
		return nil, fmt.Errorf("seal: generate salt: %w", err)
	}
	aead, err := newAEAD(dek, salt)
	if err != nil {
		return nil, err
	}
	header, err := newHeader(frameSize, salt)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("seal: write header: %w", err)
	}
	return &encryptWriter{
		w:         w,
		aead:      aead,
		addr:      addr,
		header:    header,
		frameSize: frameSize,
		buf:       make([]byte, 0, frameSize),
	}, nil
}

// NewEncryptWriter returns a WriteCloser that encrypts everything written to
// it as a framed stream to w, sealed under dek and bound to addr. The caller
// must call Close to seal the final frame; a stream that is never closed is
// never completed and cannot be decrypted.
func NewEncryptWriter(w io.Writer, dek keyring.DEK, addr domain.ObjectAddress) (io.WriteCloser, error) {
	return newEncryptWriter(w, dek, addr, rand.Reader, domain.FrameSize)
}

func (e *encryptWriter) sealFrame(plaintext []byte, final bool) error {
	nonce := frameNonce(e.index)
	ciphertext := e.aead.Seal(nil, nonce, plaintext, frameAAD(e.header, e.addr, e.index, final))
	if _, err := e.w.Write(ciphertext); err != nil {
		return fmt.Errorf("seal: write frame %d: %w", e.index, err)
	}
	e.index++
	return nil
}

func (e *encryptWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.closed {
		return 0, domain.ErrClosed
	}

	total := len(p)
	for len(p) > 0 {
		n := copy(e.buf[len(e.buf):cap(e.buf)], p)
		e.buf = e.buf[:len(e.buf)+n]
		p = p[n:]

		if len(e.buf) == e.frameSize {
			if len(p) == 0 {
				// The buffer is exactly full and this Write call has no more
				// data, but a future Write call might still supply more: don't
				// seal yet, Close will decide.
				break
			}
			if err := e.sealFrame(e.buf, false); err != nil {
				e.err = err
				return 0, err
			}
			e.buf = e.buf[:0]
		}
	}
	return total, nil
}

func (e *encryptWriter) Close() error {
	if e.closed {
		return e.err
	}
	e.closed = true
	if e.err != nil {
		return e.err
	}
	if err := e.sealFrame(e.buf, true); err != nil {
		e.err = err
		return err
	}
	return nil
}

// The four renderings. An encrypt writer holds a cipher.AEAD, and therefore
// an expanded AES key schedule derived from the caller's DEK, in an
// unexported field of a value fmt was handed as an io.WriteCloser — so
// without these, %+v reflects the round keys. There is nothing else in this
// type worth printing, which is why the placeholder is all of it.
func (e *encryptWriter) String() string             { return domain.RedactedAs("seal.EncryptWriter") }
func (e *encryptWriter) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.String()) }
func (e *encryptWriter) MarshalJSON() ([]byte, error) {
	return []byte(`"` + domain.RedactedAs("seal.EncryptWriter") + `"`), nil
}
func (e *encryptWriter) LogValue() slog.Value { return slog.StringValue(e.String()) }

// decryptReader implements io.ReadCloser over a framed stream. It decrypts and
// authenticates one frame at a time, determining whether a full-length frame
// is the stream's last by peeking for EOF before deciding which AAD to
// authenticate it against — the peek is what lets a stream truncated right
// after a non-final frame be told apart from one that legitimately ends there.
//
// Close drains and authenticates any frames the caller never read before
// reporting success, so a caller that only reads a prefix of the object still
// learns about corruption anywhere in the rest of the stream: a short Read can
// never silently suppress a later authentication failure.
type decryptReader struct {
	br        *bufio.Reader
	aead      cipher.AEAD
	addr      domain.ObjectAddress
	header    []byte // the exact header bytes read, bound into every frame's AAD
	index     uint64
	frameSize int

	// maxPlaintext is the stream's total plaintext ceiling, or
	// domain.Unlimited. It is checked against the next frame's plaintext
	// length *before* that frame is opened, so a bounded reader never
	// allocates or decrypts past its ceiling.
	maxPlaintext  int64
	plaintextSeen int64

	plain  []byte // decrypted bytes not yet returned to the caller
	done   bool   // the final frame has been authenticated
	err    error  // sticky terminal error, once set
	closed bool
}

// NewDecryptReader returns a ReadCloser that decrypts a framed stream read
// from r, which must have been sealed under dek and bound to addr.
//
// maxPlaintext bounds the stream's total plaintext: domain.Unlimited for no
// ceiling, or a positive byte count. A zero is refused — see
// domain.ValidateStreamCeiling for why this one has no default when the
// one-shot entry points do.
//
// Read returns domain.ErrCorrupt as soon as it reaches a frame that fails to
// authenticate, and a *domain.LimitError as soon as the next frame would carry
// the total past maxPlaintext. The ceiling cannot un-hand bytes the caller has
// already read, which is inherent to streaming and is why CHARTER.md's "never
// a partial result" rule is stated for the one-shot entry points: what the
// ceiling buys on a stream is that the caller's buffer stops growing, not that
// it stays empty.
//
// Close additionally authenticates every frame the caller did not read and
// returns ErrCorrupt if any of them fail, so a caller must check Close's error
// even after a successful partial read — and because that drain decrypts and
// authenticates every remaining frame, closing a reader that abandoned a read
// partway through a large object costs as much as decrypting the rest of that
// object. A download path that lets clients disconnect mid-read should account
// for that cost (for example, by not calling Close synchronously on the
// request's goroutine) rather than assume Close is free.
func NewDecryptReader(
	r io.Reader, dek keyring.DEK, addr domain.ObjectAddress, maxPlaintext int64,
) (io.ReadCloser, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}
	if err := domain.ValidateStreamCeiling(maxPlaintext); err != nil {
		return nil, err
	}
	header := make([]byte, domain.FramedHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, domain.ErrCorrupt
		}
		return nil, fmt.Errorf("seal: read header: %w", err)
	}
	frameSize, salt, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(dek, salt)
	if err != nil {
		return nil, err
	}
	return &decryptReader{
		br:           bufio.NewReader(r),
		aead:         aead,
		addr:         addr,
		header:       header,
		frameSize:    int(frameSize),
		maxPlaintext: maxPlaintext,
	}, nil
}

// nextFrame reads, authenticates, and returns the next frame's plaintext.
func (d *decryptReader) nextFrame() ([]byte, bool, error) {
	wireFrameSize := d.frameSize + d.aead.Overhead()
	buf := make([]byte, wireFrameSize)
	n, err := io.ReadFull(d.br, buf)
	switch {
	case err == nil:
		// Got a full wireFrameSize read; still need to know if more follows to
		// decide finality.
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Short final frame.
	case errors.Is(err, io.EOF):
		if n == 0 {
			// Stream ended with no frame at all where one was expected: either
			// truly empty input (never valid: the format always has at least
			// one, possibly empty, final frame) or the stream ended cleanly
			// after a previous final frame, which the caller should never reach
			// because d.done is checked first.
			return nil, false, domain.ErrCorrupt
		}
	default:
		return nil, false, fmt.Errorf("seal: read frame %d: %w", d.index, err)
	}

	ciphertext := buf[:n]
	if len(ciphertext) < d.aead.Overhead() {
		return nil, false, domain.ErrCorrupt
	}

	// Checked here, from the frame's wire length, before Open allocates the
	// plaintext — the same before-allocation rule the one-shot ceilings
	// follow, applied one frame at a time.
	if d.maxPlaintext != domain.Unlimited {
		next := d.plaintextSeen + int64(len(ciphertext)-d.aead.Overhead())
		if next > d.maxPlaintext {
			return nil, false, &domain.LimitError{
				Limit: "max plaintext", Max: d.maxPlaintext, Actual: -1,
			}
		}
	}

	final := n < wireFrameSize
	if !final {
		if _, peekErr := d.br.Peek(1); errors.Is(peekErr, io.EOF) {
			final = true
		} else if peekErr != nil {
			return nil, false, fmt.Errorf("seal: peek after frame %d: %w", d.index, peekErr)
		}
	}

	plaintext, err := d.aead.Open(
		ciphertext[:0], frameNonce(d.index), ciphertext, frameAAD(d.header, d.addr, d.index, final))
	if err != nil {
		return nil, false, domain.ErrCorrupt
	}
	d.index++
	d.plaintextSeen += int64(len(plaintext))
	return plaintext, final, nil
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		plaintext, final, err := d.nextFrame()
		if err != nil {
			d.err = err
			return 0, err
		}
		d.plain = plaintext
		if final {
			d.done = true
		}
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}

func (d *decryptReader) Close() error {
	if d.closed {
		return d.err
	}
	d.closed = true
	for d.err == nil && !d.done {
		_, final, err := d.nextFrame()
		if err != nil {
			d.err = err
			break
		}
		if final {
			d.done = true
		}
	}
	return d.err
}

// The four renderings; see encryptWriter's.
func (d *decryptReader) String() string             { return domain.RedactedAs("seal.DecryptReader") }
func (d *decryptReader) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }
func (d *decryptReader) MarshalJSON() ([]byte, error) {
	return []byte(`"` + domain.RedactedAs("seal.DecryptReader") + `"`), nil
}
func (d *decryptReader) LogValue() slog.Value { return slog.StringValue(d.String()) }

// rangeReader is an io.Reader over the plaintext bytes of one requested range
// of a framed stream. It decrypts at most one frame at a time, lazily, as Read
// is called, so it never holds more than one frame's worth of plaintext in
// memory regardless of how large the requested range is, and a caller who only
// reads the first few bytes of a huge range never pays to decrypt the rest.
type rangeReader struct {
	ra     io.ReaderAt
	aead   cipher.AEAD
	addr   domain.ObjectAddress
	header []byte // the exact header bytes read, bound into every frame's AAD

	frameSize          int64
	wireFrameSize      int64
	numFrames          int64
	lastFrameCipherLen int64

	off int64 // requested start, in plaintext bytes
	end int64 // requested end, exclusive, in plaintext bytes

	nextIndex int64 // next frame index to decrypt
	endIndex  int64 // last frame index needed, inclusive; nextIndex > endIndex means exhausted

	pending []byte // decrypted bytes from the current frame, not yet returned
	err     error  // sticky terminal error, once set
}

func (r *rangeReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.nextIndex > r.endIndex {
			return 0, io.EOF
		}

		plaintext, err := r.decryptFrame(r.nextIndex)
		if err != nil {
			r.err = err
			return 0, err
		}

		frameStart := r.nextIndex * r.frameSize
		lo := int64(0)
		if r.off > frameStart {
			lo = r.off - frameStart
		}
		hi := int64(len(plaintext))
		if r.end < frameStart+int64(len(plaintext)) {
			hi = r.end - frameStart
		}
		r.pending = plaintext[lo:hi]
		r.nextIndex++
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// decryptFrame reads and authenticates frame i of the underlying stream.
func (r *rangeReader) decryptFrame(i int64) ([]byte, error) {
	final := i == r.numFrames-1
	cipherLen := r.wireFrameSize
	if final {
		cipherLen = r.lastFrameCipherLen
	}
	frameOff := int64(domain.FramedHeaderSize) + i*r.wireFrameSize

	ciphertext := make([]byte, cipherLen)
	if err := readAtFull(r.ra, ciphertext, frameOff); err != nil {
		return nil, err
	}
	plaintext, err := r.aead.Open(
		ciphertext[:0],
		frameNonce(uint64(i)), //nolint:gosec // frame index is bounded by stream size
		ciphertext,
		frameAAD(r.header, r.addr, uint64(i), final), //nolint:gosec // same
	)
	if err != nil {
		return nil, domain.ErrCorrupt
	}
	return plaintext, nil
}

// The four renderings; see encryptWriter's.
func (r *rangeReader) String() string             { return domain.RedactedAs("seal.DecryptRangeReader") }
func (r *rangeReader) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (r *rangeReader) MarshalJSON() ([]byte, error) {
	return []byte(`"` + domain.RedactedAs("seal.DecryptRangeReader") + `"`), nil
}
func (r *rangeReader) LogValue() slog.Value { return slog.StringValue(r.String()) }

// NewDecryptRangeReader returns a Reader over the plaintext bytes
// [off, off+length) of a framed stream of total size size readable through ra,
// sealed under dek and bound to addr. It decrypts one frame at a time as the
// caller reads, touching only the frames that overlap the requested range and
// holding at most one frame's plaintext in memory, so both its I/O and its
// memory use are proportional to the requested range, not to the size of the
// object.
//
// length is the range's own bound, so there is no separate ceiling parameter
// here: a ranged read already states how many plaintext bytes it wants, and a
// caller that asks for more than it can hold has said the number itself.
//
// size must be the object's authoritative stored ciphertext length, taken from
// the metadata store — never a length reported by the object store or blob
// backend at read time. Every check here (how many frames the stream has,
// which frame is final, the plaintext length a range is validated against) is
// derived from size, not rediscovered from the ciphertext itself. An object
// truncated at the storage layer, paired with a size that was adjusted to
// match, authenticates perfectly for any range that does not reach into the
// truncated part: this reader has no way to learn the object used to be
// longer. That is a deliberate scope limit, not an oversight — only a full,
// sequential NewDecryptReader pass authenticates an object end to end, and a
// ranged read's whole purpose is to avoid paying that cost. A caller that
// needs both ranged access and whole-object integrity must get size from a
// source the data's owner cannot retroactively change to match a truncation.
//
// size is also trusted not to be absurd: numFrames is computed from it without
// an overflow guard, so a size within a few bytes of math.MaxInt64 could
// overflow that computation. This is covered by the same authoritative-size
// contract above — a size that large could only come from a caller ignoring it
// — rather than defended against separately.
func NewDecryptRangeReader(
	ra io.ReaderAt, size int64, dek keyring.DEK, addr domain.ObjectAddress, off, length int64,
) (io.Reader, error) {
	if addr.IsZero() {
		return nil, fmt.Errorf("%w: no address", domain.ErrInvalidAddress)
	}
	if off < 0 || length < 0 {
		return nil, fmt.Errorf("%w: negative offset (%d) or length (%d)", domain.ErrRange, off, length)
	}
	if size < int64(domain.FramedHeaderSize) {
		return nil, domain.ErrCorrupt
	}

	header := make([]byte, domain.FramedHeaderSize)
	if err := readAtFull(ra, header, 0); err != nil {
		return nil, err
	}
	frameSize, salt, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(dek, salt)
	if err != nil {
		return nil, err
	}

	fsz := int64(frameSize)
	wireFrameSize := fsz + int64(aead.Overhead())
	cipherTotal := size - int64(domain.FramedHeaderSize)
	if cipherTotal <= 0 || cipherTotal < int64(aead.Overhead()) {
		return nil, domain.ErrCorrupt
	}
	numFrames := (cipherTotal + wireFrameSize - 1) / wireFrameSize
	lastFrameCipherLen := cipherTotal - (numFrames-1)*wireFrameSize
	if lastFrameCipherLen < int64(aead.Overhead()) {
		return nil, domain.ErrCorrupt
	}
	totalPlaintext := (numFrames-1)*fsz + (lastFrameCipherLen - int64(aead.Overhead()))

	// Checked this way round — rather than off+length > totalPlaintext — so
	// that off and length arriving from an untrusted source (an HTTP Range
	// header, say) can never overflow int64 before being rejected. off and
	// length are already known non-negative above, so totalPlaintext-off
	// cannot overflow; off+length, with both near math.MaxInt64, can wrap
	// negative and slip past a naive comparison straight into an allocation
	// sized by the wrapped (and possibly negative-cast-to-huge) result.
	if length > totalPlaintext-off {
		return nil, fmt.Errorf("%w: range off=%d length=%d past end of %d-byte object",
			domain.ErrRange, off, length, totalPlaintext)
	}

	r := &rangeReader{
		ra:                 ra,
		aead:               aead,
		addr:               addr,
		header:             header,
		frameSize:          fsz,
		wireFrameSize:      wireFrameSize,
		numFrames:          numFrames,
		lastFrameCipherLen: lastFrameCipherLen,
		off:                off,
		end:                off + length,
	}
	if length == 0 {
		r.nextIndex, r.endIndex = 0, -1 // immediately exhausted, no frame ever touched
	} else {
		r.nextIndex = off / fsz
		r.endIndex = (off + length - 1) / fsz
	}
	return r, nil
}

// readAtFull reads exactly len(buf) bytes from ra at off, treating an io.EOF
// that nonetheless filled buf (permitted by io.ReaderAt) as success, and any
// short read as corruption.
func readAtFull(ra io.ReaderAt, buf []byte, off int64) error {
	n, err := ra.ReadAt(buf, off)
	if n == len(buf) && (err == nil || errors.Is(err, io.EOF)) {
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("seal: read at %d: %w", off, err)
	}
	return domain.ErrCorrupt
}
