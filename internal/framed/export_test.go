package framed

import (
	"io"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/domain"
)

// NewEncryptWriterForTest behaves exactly like NewEncryptWriter except the
// stream's salt is drawn from randSource instead of crypto/rand, and its frame
// size is the caller's frameSize instead of the fixed FrameSize constant. It
// exists only so tests can produce deterministic ciphertext (including the
// one-time generation of the committed testdata/vectors.json fixtures) and
// exercise the decoder against frame sizes smaller than FrameSize without
// committing megabyte-sized fixtures. Production code must always go through
// NewEncryptWriter.
func NewEncryptWriterForTest(
	w io.Writer, dek keyring.DEK, addr domain.ObjectAddress, randSource io.Reader, frameSize int,
) (io.WriteCloser, error) {
	return newEncryptWriter(w, dek, addr, randSource, frameSize)
}

// FrameKeyForTest derives the per-stream frame key the way every frame of a
// stream with this salt is sealed under. It exists for one test: that no
// rendering of the writer or either reader discloses the derived key, which is
// the material those types actually hold. A test cannot assert that without
// being able to name the needle.
func FrameKeyForTest(dek keyring.DEK, salt []byte) ([]byte, error) {
	return deriveFrameKey(dek, salt)
}
