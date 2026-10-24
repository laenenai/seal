package framed_test

// These tests are cas/internal/crypto/stream_test.go, ported under their own
// names rather than rewritten, because each one is a bug someone already
// found and a renamed test is a test nobody can trace back to its bug. What
// changed is mechanical: package and identifier names, a keyring.DEK where a
// []byte used to be, an ObjectAddress where a struct literal used to be, and
// the stream reader's new plaintext ceiling passed as seal.Unlimited so the
// ported assertions mean exactly what they meant in CAS.
//
// Three tests gained something and one lost something, each noted at the test:
//
//   - TestInvalidDEK_RejectedEverywhere is narrower than CAS's
//     TestInvalidDEKLength_RejectedEverywhere, because keyring.DEK makes a
//     16-byte DEK unconstructible. The type now carries what the check used
//     to.
//   - TestNoRenderingOfAStreamTypeDisclosesTheFrameKey is new. It covers a
//     leak channel the extracted code had.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"os"
	"strings"
	"testing"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/domain"
	"github.com/laenenai/seal/internal/framed"
)

// These constants mirror the committed wire format documented in
// docs/format.md: a 25-byte header (5-byte magic + 4-byte frame size +
// 16-byte salt) followed by frames of FrameSize plaintext bytes sealed with a
// 16-byte AES-GCM tag. Tests that splice or flip raw ciphertext bytes use them
// to find exact frame boundaries; a real format change should update both the
// doc and these constants together.
const (
	headerLen     = 5 + 4 + 16
	gcmTagSize    = 16
	frameSize     = domain.FrameSize
	frameWireSize = frameSize + gcmTagSize
)

func testAddress(t *testing.T, tenant, addressHex string) domain.ObjectAddress {
	t.Helper()
	addr, err := domain.NewObjectAddress(tenant, "sha256:"+addressHex)
	if err != nil {
		t.Fatalf("NewObjectAddress(%q, %q): %v", tenant, addressHex, err)
	}
	return addr
}

func fixedAddressHex() string { return strings.Repeat("ab", 32) }

func testDEK(t *testing.T) keyring.DEK {
	t.Helper()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("keyring.NewDEK(): %v", err)
	}
	t.Cleanup(dek.Destroy)
	return dek
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func encryptAll(t *testing.T, dek keyring.DEK, addr domain.ObjectAddress, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := framed.NewEncryptWriter(&buf, dek, addr)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func decryptAll(dek keyring.DEK, addr domain.ObjectAddress, ciphertext []byte) ([]byte, error) {
	r, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, domain.Unlimited)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr != nil {
		return data, readErr
	}
	return data, closeErr
}

func TestEncryptDecrypt_RoundTripAcrossSizes(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	sizes := []int{0, 1, frameSize - 1, frameSize, frameSize + 1, 5*frameSize + 17}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			plaintext := randomBytes(t, size)
			ciphertext := encryptAll(t, dek, addr, plaintext)

			got, err := decryptAll(dek, addr, ciphertext)
			if err != nil {
				t.Fatalf("decryptAll: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip mismatch for size %d: got %d bytes, want %d bytes", size, len(got), len(plaintext))
			}
		})
	}
}

func TestDecrypt_RejectsTruncatedStream(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	// Two frames: one full non-final frame, one short final frame.
	plaintext := randomBytes(t, frameSize+17)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	finalFrameLen := 17 + gcmTagSize
	truncated := ciphertext[:len(ciphertext)-finalFrameLen]

	if _, err := decryptAll(dek, addr, truncated); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("decrypt of stream missing its final frame: err = %v, want ErrCorrupt", err)
	}
}

func TestDecrypt_RejectsDroppedMiddleFrame(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	// Exactly three full frames: two non-final, one final.
	plaintext := randomBytes(t, 3*frameSize)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	// Drop the middle frame (index 1) entirely.
	middleStart := headerLen + frameWireSize
	middleEnd := middleStart + frameWireSize
	tampered := append([]byte{}, ciphertext[:middleStart]...)
	tampered = append(tampered, ciphertext[middleEnd:]...)

	if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("decrypt with middle frame dropped: err = %v, want ErrCorrupt", err)
	}
}

func TestDecrypt_RejectsSwappedFrames(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	// Three full frames so the first two are equal-length non-final frames
	// that can be swapped without changing the stream's total length.
	plaintext := randomBytes(t, 3*frameSize)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	tampered := append([]byte{}, ciphertext...)
	frame0 := tampered[headerLen : headerLen+frameWireSize]
	frame1 := tampered[headerLen+frameWireSize : headerLen+2*frameWireSize]
	buf := make([]byte, frameWireSize)
	copy(buf, frame0)
	copy(frame0, frame1)
	copy(frame1, buf)

	if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("decrypt with swapped frames: err = %v, want ErrCorrupt", err)
	}
}

func TestDecrypt_RejectsFlippedBitInEveryFramePosition(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	// Four frames: three full non-final frames, one short final frame.
	plaintext := randomBytes(t, 3*frameSize+17)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	frameStarts := []int{
		headerLen,
		headerLen + frameWireSize,
		headerLen + 2*frameWireSize,
		headerLen + 3*frameWireSize,
	}

	for i, start := range frameStarts {
		t.Run(fmt.Sprintf("frame=%d", i), func(t *testing.T) {
			tampered := append([]byte{}, ciphertext...)
			tampered[start] ^= 0x01
			if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
				t.Fatalf("decrypt with bit flipped in frame %d: err = %v, want ErrCorrupt", i, err)
			}
		})
	}
}

func TestDecrypt_RejectsWrongAAD(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := randomBytes(t, frameSize+17)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	t.Run("other tenant", func(t *testing.T) {
		wrong := testAddress(t, "tenant-2", fixedAddressHex())
		if _, err := decryptAll(dek, wrong, ciphertext); !errors.Is(err, domain.ErrCorrupt) {
			t.Fatalf("decrypt under another tenant's AAD: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("other content address", func(t *testing.T) {
		wrong := testAddress(t, "tenant-1", strings.Repeat("cd", 32))
		if _, err := decryptAll(dek, wrong, ciphertext); !errors.Is(err, domain.ErrCorrupt) {
			t.Fatalf("decrypt under another content address's AAD: err = %v, want ErrCorrupt", err)
		}
	})
}

func TestDecrypt_RejectsTamperedHeader(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := randomBytes(t, 100)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	t.Run("frame size in range", func(t *testing.T) {
		// Flips a less-significant byte of the 4-byte frame-size field (1<<20
		// becomes 1114112), which stays within [MinFrameSize, MaxFrameSize] —
		// so this exercises the AAD binding the whole header, not the bounds
		// check below. Flipping the most-significant byte instead would push
		// the value past MaxFrameSize and get rejected by the bounds check
		// alone, which would make this subtest pass for the wrong reason.
		tampered := append([]byte{}, ciphertext...)
		tampered[6] ^= 0x01
		if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
			t.Fatalf("decrypt with an in-range tampered frame size: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("frame size out of bounds", func(t *testing.T) {
		tampered := append([]byte{}, ciphertext...)
		tampered[5] ^= 0x01 // most-significant byte of the frame-size field; pushes 1<<20 past MaxFrameSize
		if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
			t.Fatalf("decrypt with an out-of-bounds frame size: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("salt", func(t *testing.T) {
		tampered := append([]byte{}, ciphertext...)
		tampered[9] ^= 0x01 // first byte of the 16-byte salt field
		if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
			t.Fatalf("decrypt with tampered salt: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("magic", func(t *testing.T) {
		tampered := append([]byte{}, ciphertext...)
		tampered[0] ^= 0x01
		if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
			t.Fatalf("decrypt with tampered magic: err = %v, want ErrCorrupt", err)
		}
	})
}

func TestRangeReader_MatchesFullDecryptForRandomRanges(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	const size = 7*frameSize + 12345
	plaintext := randomBytes(t, size)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	rng := mrand.New(mrand.NewSource(42)) //nolint:gosec // deterministic test RNG for reproducible range selection, not cryptographic use
	for i := 0; i < 100; i++ {
		off := int64(rng.Intn(size))
		maxLen := int64(size) - off
		length := int64(0)
		if maxLen > 0 {
			length = int64(rng.Int63n(maxLen)) + 1
		}

		r, err := framed.NewDecryptRangeReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, off, length)
		if err != nil {
			t.Fatalf("NewDecryptRangeReader(off=%d, length=%d): %v", off, length, err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll(off=%d, length=%d): %v", off, length, err)
		}
		want := plaintext[off : off+length]
		if !bytes.Equal(got, want) {
			t.Fatalf("range [%d,%d) mismatch: got %d bytes, want %d bytes", off, off+length, len(got), len(want))
		}
	}
}

// countingReaderAt wraps an io.ReaderAt and records how many bytes were
// requested through it, so a test can assert that a ranged read only touches
// the frames it needs rather than the whole object.
type countingReaderAt struct {
	ra        io.ReaderAt
	bytesRead int64
	calls     int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	n, err := c.ra.ReadAt(p, off)
	c.bytesRead += int64(n)
	return n, err
}

func TestRangeReader_FrameCountProportionalToRange(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	const size = 7 * frameSize
	plaintext := randomBytes(t, size)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	counter := &countingReaderAt{ra: bytes.NewReader(ciphertext)}
	// A small range entirely inside frame index 3; should touch at most one
	// frame's worth of ciphertext plus the header, never the whole object.
	off := int64(3*frameSize + 10)
	length := int64(100)

	r, err := framed.NewDecryptRangeReader(counter, int64(len(ciphertext)), dek, addr, off, length)
	if err != nil {
		t.Fatalf("NewDecryptRangeReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if want := plaintext[off : off+length]; !bytes.Equal(got, want) {
		t.Fatalf("range contents mismatch")
	}

	const maxExpectedBytes = headerLen + 2*frameWireSize // generous slack, still « 7 frames
	if counter.bytesRead > maxExpectedBytes {
		t.Errorf("ranged read touched %d bytes of ciphertext, want <= %d (object is %d bytes): range read is not proportional to the request",
			counter.bytesRead, maxExpectedBytes, len(ciphertext))
	}
}

func TestDecryptReader_PartialReadThenCorruptTail_CloseReportsError(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	// Two full frames: reading only the first one must not hide corruption
	// planted in the second.
	plaintext := randomBytes(t, 2*frameSize)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	lastFrameStart := headerLen + frameWireSize
	ciphertext[lastFrameStart] ^= 0x01

	r, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, domain.Unlimited)
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}

	small := make([]byte, 10)
	n, err := r.Read(small)
	if err != nil {
		t.Fatalf("Read of first frame: err = %v, want nil (corruption is in the second frame)", err)
	}
	if n != len(small) {
		t.Fatalf("Read = %d bytes, want %d", n, len(small))
	}

	if err := r.Close(); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("Close() after a short read of an object whose tail is corrupt: err = %v, want ErrCorrupt", err)
	}
}

func TestDecryptReader_PartialReadOfCleanObject_CloseReturnsNil(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := randomBytes(t, 2*frameSize)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	r, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, domain.Unlimited)
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}

	small := make([]byte, 10)
	if _, err := r.Read(small); err != nil {
		t.Fatalf("Read of first frame: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close() after a short read of a clean object: err = %v, want nil", err)
	}
}

// TestVectors_MatchCommittedTestdata is the test that makes this an
// extraction. Every byte of testdata/vectors.json came across from
// cas/internal/crypto/testdata/vectors.json unchanged, and this test decrypts
// each entry's committed ciphertext directly: CAS's ciphertext, CAS's DEK,
// CAS's tenant and content address, decrypted by this module's code. If it
// ever fails, the wire format has changed, and the answer is to change it back
// — not to refresh the vector.
func TestVectors_MatchCommittedTestdata(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read testdata/vectors.json: %v", err)
	}

	var doc struct {
		Vectors []struct {
			Name    string `json:"name"`
			DEKHex  string `json:"dek_hex"`
			Tenant  string `json:"tenant_id"`
			Address struct {
				Algo string `json:"algo"`
				Hex  string `json:"hex"`
			} `json:"content_address"`
			PlaintextHex  string `json:"plaintext_hex"`
			CiphertextHex string `json:"ciphertext_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal vectors.json: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("testdata/vectors.json has no vectors")
	}

	// More than one vector is committed deliberately: see docs/format.md,
	// "Test vectors", for why a single small vector (index 0, final=true)
	// cannot by itself catch several plausible wire-format regressions.
	for _, vec := range doc.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			dekBytes, err := hex.DecodeString(vec.DEKHex)
			if err != nil {
				t.Fatalf("decode dek_hex: %v", err)
			}
			dek, err := keyring.DEKFrom(dekBytes)
			if err != nil {
				t.Fatalf("keyring.DEKFrom(dek_hex): %v", err)
			}
			defer dek.Destroy()

			wantPlaintext, err := hex.DecodeString(vec.PlaintextHex)
			if err != nil {
				t.Fatalf("decode plaintext_hex: %v", err)
			}
			ciphertext, err := hex.DecodeString(vec.CiphertextHex)
			if err != nil {
				t.Fatalf("decode ciphertext_hex: %v", err)
			}

			// The object component is the content address's canonical
			// "<algo>:<hex>" form, which is the string CAS bound into every
			// frame's AAD. The vector's content_address is stored as its two
			// parts so the fixture records what CAS's domain type held, not
			// just the concatenation.
			addr, err := domain.NewObjectAddress(vec.Tenant, vec.Address.Algo+":"+vec.Address.Hex)
			if err != nil {
				t.Fatalf("NewObjectAddress: %v", err)
			}

			// Decrypt the committed bytes directly. This must never be
			// replaced by encrypting wantPlaintext afresh and comparing
			// ciphertexts or round-tripping: the whole point of this test is
			// that a change to the wire format breaks it, which only
			// decrypting a byte-for-byte pinned fixture can detect.
			got, err := decryptAll(dek, addr, ciphertext)
			if err != nil {
				t.Fatalf("decrypt committed vector %q: %v", vec.Name, err)
			}
			if !bytes.Equal(got, wantPlaintext) {
				t.Fatalf("decrypted vector %q = %x, want %x", vec.Name, got, wantPlaintext)
			}
		})
	}
}

// TestCanary_NoSecretsLeakInErrors forces every decryption failure path with a
// plaintext and a DEK that each embed a distinct sentinel value, and asserts
// that no returned error ever contains either sentinel, in ASCII or hex form.
// No error, log line, or test failure message may contain key material or
// plaintext.
func TestCanary_NoSecretsLeakInErrors(t *testing.T) {
	const plaintextSentinel = "PLAINTEXT-CANARY-SENTINEL-19a2f"
	dekSentinel := "DEK-CANARY-SENTINEL-0b73c91d2e4f" // exactly 32 bytes
	if len(dekSentinel) != 32 {
		t.Fatalf("test bug: dekSentinel must be exactly 32 bytes, is %d", len(dekSentinel))
	}
	dek, err := keyring.DEKFrom([]byte(dekSentinel))
	if err != nil {
		t.Fatalf("keyring.DEKFrom(sentinel): %v", err)
	}
	defer dek.Destroy()

	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := []byte("prefix-" + plaintextSentinel + "-suffix")

	ciphertext := encryptAll(t, dek, addr, plaintext)

	forbidden := []string{
		plaintextSentinel,
		dekSentinel,
		hex.EncodeToString([]byte(dekSentinel)),
	}
	check := func(t *testing.T, label string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: err = nil, want an error (test setup didn't actually force a failure)", label)
		}
		msg := err.Error()
		for _, s := range forbidden {
			if strings.Contains(msg, s) {
				t.Errorf("%s: error %q leaks sentinel %q", label, msg, s)
			}
		}
	}

	// Wrong AAD.
	_, err = decryptAll(dek, testAddress(t, "tenant-2", fixedAddressHex()), ciphertext)
	check(t, "wrong AAD", err)

	// Tampered header (salt).
	tamperedHeader := append([]byte{}, ciphertext...)
	tamperedHeader[9] ^= 0x01
	_, err = decryptAll(dek, addr, tamperedHeader)
	check(t, "tampered header", err)

	// Flipped bit in the frame.
	tamperedFrame := append([]byte{}, ciphertext...)
	tamperedFrame[headerLen] ^= 0x01
	_, err = decryptAll(dek, addr, tamperedFrame)
	check(t, "flipped frame bit", err)

	// Truncated stream (drop everything after the header).
	_, err = decryptAll(dek, addr, ciphertext[:headerLen])
	check(t, "truncated stream", err)

	// Range reader over a tampered object.
	rr, err := framed.NewDecryptRangeReader(
		bytes.NewReader(tamperedFrame), int64(len(tamperedFrame)), dek, addr, 0, int64(len(plaintext)))
	if err != nil {
		check(t, "range reader construction", err)
	} else {
		_, err = io.ReadAll(rr)
		check(t, "range reader read", err)
	}

	// Partial-read-then-Close on a tail-corrupted multi-frame object.
	big := randomBytes(t, 2*frameSize)
	bigCipher := encryptAll(t, dek, addr, big)
	bigCipher[headerLen+frameWireSize] ^= 0x01
	r, err := framed.NewDecryptReader(bytes.NewReader(bigCipher), dek, addr, domain.Unlimited)
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	_, _ = r.Read(make([]byte, 10))
	check(t, "Close after partial read of corrupt tail", r.Close())
}

// encryptAllWithFrameSize is like encryptAll but uses the package's test-only
// small-frame-size seam, so tests can exercise a stream with several frames
// without the plaintext (or the committed vector) needing to be megabytes
// large.
func encryptAllWithFrameSize(
	t *testing.T, dek keyring.DEK, addr domain.ObjectAddress, plaintext []byte, frameSize int,
) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := framed.NewEncryptWriterForTest(&buf, dek, addr, rand.Reader, frameSize)
	if err != nil {
		t.Fatalf("NewEncryptWriterForTest: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// TestEncryptDecrypt_HonorsFrameSizeFromHeader proves the decoder actually
// reads frame_size from the header and frames accordingly, rather than
// assuming the production FrameSize constant everywhere. A decoder that
// ignored the header's frame_size would garble this round trip (or fail it
// outright), since every frame boundary here is a fraction of FrameSize.
func TestEncryptDecrypt_HonorsFrameSizeFromHeader(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	const smallFrameSize = 64
	// Two full small frames plus a short final one.
	plaintext := randomBytes(t, 2*smallFrameSize+10)

	ciphertext := encryptAllWithFrameSize(t, dek, addr, plaintext, smallFrameSize)

	got, err := decryptAll(dek, addr, ciphertext)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch with a header-declared small frame size")
	}
}

func TestNewEncryptWriterForTest_RejectsFrameSizeOutOfBounds(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	for _, fs := range []int{0, 1, domain.MinFrameSize - 1, domain.MaxFrameSize + 1} {
		if _, err := framed.NewEncryptWriterForTest(&bytes.Buffer{}, dek, addr, rand.Reader, fs); err == nil {
			t.Errorf("frameSize=%d: err = nil, want an error", fs)
		}
	}
}

// TestInvalidDEK_RejectedEverywhere forces the DEK check in every constructor
// that accepts one. It is CAS's TestInvalidDEKLength_RejectedEverywhere,
// narrowed, and the narrowing is the type doing its job rather than coverage
// being dropped.
//
// CAS took a bare []byte and had to reject nil, empty, 16 bytes and 33 bytes,
// because without that check HKDF derived a usable-looking key from a nil or
// short secret with no error, silently sealing data under key material an
// attacker could recompute from the stream's public salt. keyring.DEK makes
// every one of those cases unconstructible: the material is unexported and
// DEKFrom validates it. What remains is the case no type can refuse to
// represent — a DEK used after Destroy — and that one is still here.
func TestInvalidDEK_RejectedEverywhere(t *testing.T) {
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	goodDEK := testDEK(t)
	ciphertext := encryptAll(t, goodDEK, addr, []byte("hello, world"))

	destroyed, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("keyring.NewDEK(): %v", err)
	}
	destroyed.Destroy()

	badDEKs := map[string]keyring.DEK{
		"zero value": {},
		"destroyed":  destroyed,
	}
	for name, dek := range badDEKs {
		t.Run(name, func(t *testing.T) {
			if _, err := framed.NewEncryptWriter(&bytes.Buffer{}, dek, addr); !errors.Is(err, domain.ErrInvalidDEK) {
				t.Errorf("NewEncryptWriter: err = %v, want ErrInvalidDEK", err)
			}
			if _, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, domain.Unlimited); !errors.Is(err, domain.ErrInvalidDEK) {
				t.Errorf("NewDecryptReader: err = %v, want ErrInvalidDEK", err)
			}
			if _, err := framed.NewDecryptRangeReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, 0, 1); !errors.Is(err, domain.ErrInvalidDEK) {
				t.Errorf("NewDecryptRangeReader: err = %v, want ErrInvalidDEK", err)
			}
		})
	}
}

func TestEncryptWriter_WriteAfterCloseReturnsErrClosed(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	var buf bytes.Buffer
	w, err := framed.NewEncryptWriter(&buf, dek, addr)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("more")); !errors.Is(err, domain.ErrClosed) {
		t.Fatalf("Write after Close: err = %v, want ErrClosed", err)
	}
}

func TestRangeReader_RejectsNegativeOffsetOrLength(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	ciphertext := encryptAll(t, dek, addr, randomBytes(t, 100))

	cases := []struct{ off, length int64 }{
		{-1, 10},
		{0, -1},
	}
	for _, tc := range cases {
		if _, err := framed.NewDecryptRangeReader(
			bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, tc.off, tc.length,
		); !errors.Is(err, domain.ErrRange) {
			t.Errorf("off=%d length=%d: err = %v, want ErrRange", tc.off, tc.length, err)
		}
	}
}

func TestRangeReader_RejectsRangePastEnd(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := randomBytes(t, 100)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	if _, err := framed.NewDecryptRangeReader(
		bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, 50, 100,
	); !errors.Is(err, domain.ErrRange) {
		t.Errorf("range past end: err = %v, want ErrRange", err)
	}
}

// TestRangeReader_RejectsOverflowingRangeWithoutPanicking is a regression
// test: off and length arrive from untrusted input (an HTTP Range header,
// say), and off+length can wrap a negative int64 when both are huge. A prior
// implementation compared off+length against the object's plaintext size
// directly, which passed this wrapped value straight through to an allocation
// sized by it. This must be rejected as ErrRange, not panic.
func TestRangeReader_RejectsOverflowingRangeWithoutPanicking(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	ciphertext := encryptAll(t, dek, addr, randomBytes(t, 100))

	const huge = int64(1) << 62
	_, err := framed.NewDecryptRangeReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, huge, huge)
	if !errors.Is(err, domain.ErrRange) {
		t.Fatalf("NewDecryptRangeReader(off=length=1<<62): err = %v, want ErrRange", err)
	}
}

// TestRangeReader_DecryptsLazilyOneFrameAtATime proves a range reader
// constructed over a whole-object range does not eagerly decrypt (or even
// read) more than the header before the caller starts reading, and touches
// only about one frame's worth of ciphertext to satisfy a small Read, even
// though the requested range spans the entire multi-frame object. This is what
// keeps a huge ranged read's memory bounded to one frame rather than the whole
// requested range.
func TestRangeReader_DecryptsLazilyOneFrameAtATime(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	const size = 5 * frameSize
	plaintext := randomBytes(t, size)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	counter := &countingReaderAt{ra: bytes.NewReader(ciphertext)}
	r, err := framed.NewDecryptRangeReader(counter, int64(len(ciphertext)), dek, addr, 0, int64(size))
	if err != nil {
		t.Fatalf("NewDecryptRangeReader: %v", err)
	}
	if counter.bytesRead > headerLen {
		t.Fatalf("constructing a range reader touched %d ciphertext bytes before any Read, want at most the %d-byte header: frames must be decrypted lazily",
			counter.bytesRead, headerLen)
	}

	small := make([]byte, 10)
	if _, err := io.ReadFull(r, small); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if maxExpected := int64(headerLen + frameWireSize); counter.bytesRead > maxExpected {
		t.Fatalf("after reading 10 bytes of a whole-object range, %d ciphertext bytes were touched, want <= %d: more than one frame was buffered ahead",
			counter.bytesRead, maxExpected)
	}
	if !bytes.Equal(small, plaintext[:10]) {
		t.Fatalf("content mismatch on the first 10 bytes")
	}
}

// TestRangeReader_SizeMustBeAuthoritative_KnownLimitation pins a documented,
// intentional limitation of NewDecryptRangeReader (see its doc comment and
// docs/format.md): its integrity checks are entirely derived from the
// caller-supplied size. If size is sourced from the object store rather than
// from trusted metadata, an attacker who truncates the stored object and
// reports a matching (smaller) size can make a range read that never reaches
// the truncated part succeed silently — this is not a bug to fix here, since
// only a full NewDecryptReader pass can authenticate an entire object end to
// end, and a ranged read's whole purpose is to avoid that cost. This test
// exists so a future change that makes the range reader even less likely to
// notice such tampering doesn't slip by unremarked.
func TestRangeReader_SizeMustBeAuthoritative_KnownLimitation(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := randomBytes(t, 7*frameSize)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	// Simulate an attacker truncating the stored object to its first three
	// frames, with a reported size that matches the truncation exactly (as a
	// Stat of the tampered object would report).
	truncated := ciphertext[:headerLen+3*frameWireSize]

	r, err := framed.NewDecryptRangeReader(bytes.NewReader(truncated), int64(len(truncated)), dek, addr, 10, 50)
	if err != nil {
		t.Fatalf("NewDecryptRangeReader on a truncated-but-self-consistent object: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if want := plaintext[10:60]; !bytes.Equal(got, want) {
		t.Fatalf("range contents mismatch")
	}
	// No error reached this point: the truncation of frames 3-6 went
	// undetected, because the requested range never touched them. This is the
	// documented limitation, not a bug.
}

// TestDecrypt_RejectsAlteredInRangeFrameSizeOnSingleFrameObject is a direct
// regression test for a gap introduced between CAS's fix rounds 1 and 2: once
// the decoder honored the header's frame_size, a single-frame object (one
// shorter than FrameSize) could have its frame_size field rewritten to any
// other value still inside [MinFrameSize, MaxFrameSize] and still decrypt,
// because the short-final-frame path reads whatever ciphertext remains
// regardless of what frame_size claims. Binding the whole header into every
// frame's AAD closes this: these exact altered values (reproduced from the
// values a reviewer found decrypting cleanly before the fix) must now all be
// rejected.
func TestDecrypt_RejectsAlteredInRangeFrameSizeOnSingleFrameObject(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	plaintext := randomBytes(t, 100)
	ciphertext := encryptAll(t, dek, addr, plaintext)

	for _, fs := range []uint32{1024, 1048577, 2097152, domain.MaxFrameSize} {
		t.Run(fmt.Sprintf("frame_size=%d", fs), func(t *testing.T) {
			tampered := append([]byte{}, ciphertext...)
			binary.BigEndian.PutUint32(tampered[5:9], fs)
			if _, err := decryptAll(dek, addr, tampered); !errors.Is(err, domain.ErrCorrupt) {
				t.Fatalf("decrypt with frame_size rewritten to %d (in range): err = %v, want ErrCorrupt", fs, err)
			}
		})
	}
}

// TestDecryptReader_EnforcesTheStreamPlaintextCeiling is CHARTER.md's fifth
// ceiling rule: streaming is not exempt from bounding. Streaming bounds this
// package's memory to one frame; a caller streaming into a buffer has exactly
// the same exposure it would have from a one-shot call, so the reader takes a
// total plaintext ceiling.
//
// The ceiling is checked from the next frame's wire length before that frame
// is opened, so nothing is decrypted past it — but it cannot un-hand bytes
// the caller has already read, and this test pins that honestly rather than
// pretending otherwise.
func TestDecryptReader_EnforcesTheStreamPlaintextCeiling(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	const smallFrameSize = 64
	plaintext := randomBytes(t, 4*smallFrameSize)
	ciphertext := encryptAllWithFrameSize(t, dek, addr, plaintext, smallFrameSize)

	t.Run("a ceiling the object exceeds refuses with a LimitError", func(t *testing.T) {
		r, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, 2*smallFrameSize)
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		got, err := io.ReadAll(r)
		if !errors.Is(err, domain.ErrLimitExceeded) {
			t.Fatalf("ReadAll of a stream over its ceiling: err = %v, want ErrLimitExceeded", err)
		}
		var limitErr *domain.LimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("err = %v, want a *domain.LimitError naming the ceiling", err)
		}
		if limitErr.Limit != "max plaintext" {
			t.Errorf("LimitError.Limit = %q, want %q", limitErr.Limit, "max plaintext")
		}
		if limitErr.Max != 2*smallFrameSize {
			t.Errorf("LimitError.Max = %d, want %d", limitErr.Max, 2*smallFrameSize)
		}
		if int64(len(got)) > limitErr.Max {
			t.Errorf("the reader handed back %d bytes before refusing, more than the %d-byte ceiling", len(got), limitErr.Max)
		}
		if err := r.Close(); !errors.Is(err, domain.ErrLimitExceeded) {
			t.Errorf("Close after a ceiling refusal: err = %v, want the same sticky ErrLimitExceeded", err)
		}
	})

	t.Run("a ceiling the object fits under is invisible", func(t *testing.T) {
		r, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, int64(len(plaintext)))
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll with an exactly-sufficient ceiling: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("round trip mismatch under a sufficient ceiling")
		}
	})

	t.Run("zero is refused rather than meaning unbounded", func(t *testing.T) {
		if _, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, 0); !errors.Is(err, domain.ErrInvalidLimit) {
			t.Fatalf("NewDecryptReader with a zero ceiling: err = %v, want ErrInvalidLimit", err)
		}
	})
}

// TestNoRenderingOfAStreamTypeDisclosesTheFrameKey covers a leak channel the
// extracted code had, and it is here rather than in sealtest because the
// needle — the derived frame key — is reachable only through this package's
// test seam.
//
// The writer and both readers hold a cipher.AEAD, and therefore an expanded
// AES key schedule whose first words are the derived frame key. They are
// returned as io.WriteCloser and io.Reader, so fmt is handed a value whose
// concrete type has only unexported fields: without fmt.Formatter it abandons
// the method path and reflects the whole subtree, round keys included. That is
// CONVENTIONS.md's "redaction is not inherited through an unexported field",
// one level deeper than the usual case, since the material is inside a
// standard-library type nobody here wrote.
func TestNoRenderingOfAStreamTypeDisclosesTheFrameKey(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "tenant-1", fixedAddressHex())
	ciphertext := encryptAll(t, dek, addr, randomBytes(t, 100))

	// The salt is the header's last 16 bytes, so the key every frame of this
	// particular stream was sealed under is derivable here.
	salt := ciphertext[9:headerLen]
	frameKey, err := framed.FrameKeyForTest(dek, salt)
	if err != nil {
		t.Fatalf("FrameKeyForTest: %v", err)
	}

	w, err := framed.NewEncryptWriter(io.Discard, dek, addr)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	dr, err := framed.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, domain.Unlimited)
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	rr, err := framed.NewDecryptRangeReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, 0, 10)
	if err != nil {
		t.Fatalf("NewDecryptRangeReader: %v", err)
	}

	// A variable rather than literal format strings: go vet's printf analyzer
	// only inspects constant formats, and a literal fmt.Sprintf("%d", w) here
	// would be a vet failure in CI for code whose purpose is to provoke that
	// case.
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%U", "%b", "%o"}

	for name, subject := range map[string]any{"EncryptWriter": w, "DecryptReader": dr, "DecryptRangeReader": rr} {
		t.Run(name, func(t *testing.T) {
			var rendered []string
			for _, verb := range verbs {
				rendered = append(rendered, fmt.Sprintf(verb, subject))
				rendered = append(rendered, fmt.Sprintf(verb, struct{ V any }{subject}))
			}
			if b, err := json.Marshal(subject); err == nil {
				rendered = append(rendered, string(b))
			} else {
				rendered = append(rendered, err.Error())
			}
			var logged strings.Builder
			slog.New(slog.NewTextHandler(&logged, nil)).Info("rendering", slog.Any("v", subject))
			slog.New(slog.NewJSONHandler(&logged, nil)).Info("rendering", slog.Any("v", subject))
			rendered = append(rendered, logged.String())

			needles := map[string]string{
				"the frame key":     string(frameKey),
				"its lowercase hex": hex.EncodeToString(frameKey),
				"its uppercase hex": strings.ToUpper(hex.EncodeToString(frameKey)),
			}
			// What reflection of a cipher.AEAD actually prints is the key
			// schedule's uint32 words, so the first four words of the derived
			// key are the needle that would catch it in the forms %d, %#v and
			// friends emit.
			for i := 0; i+4 <= len(frameKey); i += 4 {
				word := uint32(frameKey[i])<<24 | uint32(frameKey[i+1])<<16 | uint32(frameKey[i+2])<<8 | uint32(frameKey[i+3])
				needles[fmt.Sprintf("key schedule word %d in decimal", i/4)] = fmt.Sprintf("%d", word)
			}

			for _, out := range rendered {
				for what, needle := range needles {
					if needle != "" && strings.Contains(out, needle) {
						t.Errorf("a rendering disclosed %s: %q", what, out)
					}
				}
				if !strings.Contains(strings.ToLower(out), "redact") {
					t.Errorf("rendering %q carries no redaction marker: a reader cannot tell a redacted key from an absent field", out)
				}
			}
		})
	}
}
