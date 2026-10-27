// Package sealtest is the conformance suite for seal's two ports:
// RunStreamSealerSuite and RunRecordSealerSuite are the authoritative
// description of each contract's edge-case behaviour, and an implementation
// counts as correct when it passes the suite unchanged.
//
// It is a sibling package rather than a suite.go inside the facade, and rather
// than a _test.go file, because both alternatives fail a requirement:
//
//   - Identifiers declared in a _test.go file are not importable from outside
//     that package, and this suite must be callable from another module
//     entirely. CAS has a working framed implementation of its own and will
//     run this suite against it on the way to swapping it out, which is what
//     makes "adopted" testable rather than asserted.
//   - A non-test file that imports testing makes testing a dependency of the
//     production package, so every consumer's binary links it and inherits its
//     flag registrations. Keeping the suite here keeps testing out of the
//     production import graph.
//
// This is the standard library's own shape: net/http/httptest is a sibling of
// net/http, and testing/fstest.TestFS verifies any fs.FS.
//
// # What the suite proves, and what it cannot
//
// It proves the contract, and the subtests named after CHARTER.md's properties
// exist so that no implementation can quietly skip one: the relocation
// refusal, bit-flip and truncation detection, the ranged read's agreement with
// a full decrypt, each of the five ceiling rules, and the rendering
// discipline.
//
// What it cannot prove is anything that needs the wire format to be *known*,
// because the port deliberately does not expose one. Rewriting an in-range
// frame_size and decrypting a committed ciphertext are format-specific, and
// they live in internal/framed's and internal/compact's own tests — which is
// where the ported CAS tests and the committed vectors are. A suite that
// hardcoded a layout to reach them would only ever pass for one
// implementation.
//
// Two of the assertions here are deliberately stronger than their
// format-specific counterparts rather than weaker: a bit is flipped at every
// byte position of a small ciphertext, and the ciphertext is truncated at
// every length, both of which subsume "flip a byte in the header" without
// needing to know where it is.
//
// # The frame-level properties, and how they are reached
//
// They do not subsume anything that needs a *second* frame, and for a long
// while nothing here had one: every tamper sweep encrypted 200 bytes against a
// 1 MiB seal.FrameSize, so every sweep ran over a single-frame stream.
// Truncating one frame at every length is not a dropped final frame, and
// flipping every bit of one frame never moves a frame within a stream, so the
// frame-index binding was reachable only from internal/framed — which no other
// module can import.
//
// frames.go closes that: a three-frame fixture, with a dropped final frame, a
// dropped interior frame and two swapped frames each a named subtest, over a
// geometry *measured* from the implementation under test rather than assumed
// from a layout. Its header comment carries the measurement, the sampling and
// why the sampling must stay.
package sealtest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"testing"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal"
)

// knownMaterial is the DEK material the rendering subtests use as their
// needle. It is a fixed, obviously-synthetic value rather than a random one so
// that a failure message names something a reader recognises as the test's own
// key, and it is long enough that the shared helper's containment checks are
// assertions rather than coin tosses.
var knownMaterial = []byte("sealtest-dek-material-7f3a9c1e04")

// RunStreamSealerSuite runs the contract every seal.StreamSealer
// implementation must satisfy.
//
// newSealer is called once per subtest, receiving that subtest's own *T, so an
// implementation that needs per-test setup and teardown registers it with
// t.Cleanup inside newSealer and gets fresh, isolated state for every subtest.
//
// Every assertion here must hold for any implementation of the framed format
// family. Nothing inspects the wire format or assumes a particular layout;
// format-specific mechanics belong in that format's own test file.
func RunStreamSealerSuite(t *testing.T, newSealer func(t *testing.T) seal.StreamSealer) {
	t.Helper()

	t.Run("RoundTripsAcrossSizes", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)

		sizes := []int{0, 1, 100, 65536, seal.FrameSize - 1, seal.FrameSize, seal.FrameSize + 1}
		for _, size := range sizes {
			t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
				plaintext := patterned(size)
				ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)
				got, err := s.DecryptObject(dek, addr, ciphertext, seal.Limits{MaxPlaintext: seal.Unlimited})
				if err != nil {
					t.Fatalf("DecryptObject: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("round trip mismatch at %d bytes", size)
				}
			})
		}
	})

	t.Run("StreamingRoundTripMatchesTheOneShot", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		plaintext := patterned(3 * 4096)

		var buf bytes.Buffer
		w, err := s.NewEncryptWriter(&buf, dek, addr)
		if err != nil {
			t.Fatalf("NewEncryptWriter: %v", err)
		}
		for off := 0; off < len(plaintext); off += 4096 {
			if _, err := w.Write(plaintext[off : off+4096]); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		r, err := s.NewDecryptReader(bytes.NewReader(buf.Bytes()), dek, addr, seal.Unlimited)
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("streaming round trip mismatch")
		}
	})

	// The frame-level properties: a dropped final frame, a dropped interior
	// frame, two swapped frames, and sampled flip and truncation sweeps over a
	// three-frame stream. See frames.go, and the package comment above for why
	// the single-frame sweeps below do not cover them.
	runMultiFrameSubtests(t, newSealer)

	// A security property, and stronger than picking positions: every byte of
	// a small ciphertext is flipped in turn, which covers the header, every
	// tag and every ciphertext byte without the suite needing to know where
	// any of them sit. It is a *single-frame* stream, though — 200 bytes
	// against a 1 MiB frame — so it says nothing about a frame's position in a
	// stream. That is runMultiFrameSubtests's job.
	t.Run("DetectsAFlippedBitAnywhere", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(200))

		for i := range ciphertext {
			tampered := append([]byte{}, ciphertext...)
			tampered[i] ^= 0x01
			if _, err := s.DecryptObject(dek, addr, tampered, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
				t.Errorf("byte %d of %d flipped: err = %v, want ErrCorrupt", i, len(ciphertext), err)
			}
		}
	})

	// A security property, exhaustive over a single-frame stream: every
	// truncation of it is refused, without the suite needing to know where a
	// frame boundary falls. It does not subsume "the stream's final frame was
	// dropped", because this fixture has only one frame and nothing is left
	// after dropping it; DetectsADroppedFinalFrame in frames.go is that
	// property.
	t.Run("DetectsEveryTruncation", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(200))

		for n := 0; n < len(ciphertext); n++ {
			if _, err := s.DecryptObject(dek, addr, ciphertext[:n], seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
				t.Errorf("truncated to %d of %d bytes: err = %v, want ErrCorrupt", n, len(ciphertext), err)
			}
		}
	})

	// A security property, and the module's central claim: ciphertext is bound
	// to exactly one object of exactly one tenant, so a stream cannot be
	// spliced or replayed from one object into another even within the same
	// tenant.
	t.Run("RefusesCiphertextSealedForAnotherObject", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(200))

		for name, parts := range map[string][2]string{
			"another tenant":              {"tenant-2", "sha256:" + hexRepeat("ab", 32)},
			"another object, same tenant": {"tenant-1", "sha256:" + hexRepeat("cd", 32)},
			"both":                        {"tenant-2", "sha256:" + hexRepeat("cd", 32)},
		} {
			t.Run(name, func(t *testing.T) {
				wrong, err := seal.NewObjectAddress(parts[0], parts[1])
				if err != nil {
					t.Fatalf("NewObjectAddress: %v", err)
				}
				if _, err := s.DecryptObject(dek, wrong, ciphertext, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
					t.Fatalf("opened under %s: err = %v, want ErrCorrupt", name, err)
				}
			})
		}
	})

	t.Run("RefusesAnotherDEK", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(200))

		other, err := keyring.NewDEK()
		if err != nil {
			t.Fatalf("keyring.NewDEK: %v", err)
		}
		defer other.Destroy()
		if _, err := s.DecryptObject(other, addr, ciphertext, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("opened under another DEK: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("RefusesADEKThatHoldsNoMaterial", func(t *testing.T) {
		s := newSealer(t)
		_, addr := streamFixture(t)

		destroyed, err := keyring.NewDEK()
		if err != nil {
			t.Fatalf("keyring.NewDEK: %v", err)
		}
		destroyed.Destroy()

		// Every entry point, not only the two that encrypt. A check that runs
		// before any key is derived is the control — HKDF derives a
		// usable-looking 32-byte key from an empty secret with no error of its
		// own, and the salt is public — and a decrypt constructor that skipped
		// it would derive that key from nothing and then fail to authenticate,
		// reporting ErrCorrupt for what is actually a destroyed DEK. Checking
		// only the encrypt side was the third of the three weaknesses CAS
		// measured in this suite.
		good := NewDEK(t)
		ciphertext := mustEncryptObject(t, s, good, addr, patterned(200))

		for name, dek := range map[string]seal.DEK{"zero value": {}, "destroyed": destroyed} {
			t.Run(name, func(t *testing.T) {
				if _, err := s.NewEncryptWriter(io.Discard, dek, addr); !errors.Is(err, seal.ErrInvalidDEK) {
					t.Errorf("NewEncryptWriter: err = %v, want ErrInvalidDEK", err)
				}
				if _, err := s.EncryptObject(dek, addr, []byte("v"), seal.Limits{}); !errors.Is(err, seal.ErrInvalidDEK) {
					t.Errorf("EncryptObject: err = %v, want ErrInvalidDEK", err)
				}
				if _, err := s.NewDecryptReader(
					bytes.NewReader(ciphertext), dek, addr, seal.Unlimited,
				); !errors.Is(err, seal.ErrInvalidDEK) {
					t.Errorf("NewDecryptReader: err = %v, want ErrInvalidDEK", err)
				}
				if _, err := s.NewDecryptRangeReader(
					bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, 0, 1,
				); !errors.Is(err, seal.ErrInvalidDEK) {
					t.Errorf("NewDecryptRangeReader: err = %v, want ErrInvalidDEK", err)
				}
				if _, err := s.DecryptObject(dek, addr, ciphertext, seal.Limits{}); !errors.Is(err, seal.ErrInvalidDEK) {
					t.Errorf("DecryptObject: err = %v, want ErrInvalidDEK", err)
				}
			})
		}
	})

	// A security property in the sense that matters for a read path: a ranged
	// read must return exactly what a full decrypt would, or a range handler
	// silently serves the wrong bytes.
	t.Run("RangedReadMatchesFullDecrypt", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)

		size := 2*seal.FrameSize + 1234
		plaintext := patterned(size)
		ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)

		iterations := 100
		if testing.Short() {
			// Skipped down rather than skipped out: the property is cheap to
			// sample and expensive to sweep, and the inner loop is meant to
			// stay an inner loop. This is a runtime decision, never a build
			// tag.
			iterations = 10
		}
		rng := mrand.New(mrand.NewSource(1)) //nolint:gosec // deterministic test RNG for reproducible ranges, not cryptographic use
		for i := 0; i < iterations; i++ {
			off := int64(rng.Intn(size))
			length := int64(rng.Intn(size-int(off))) + 1
			r, err := s.NewDecryptRangeReader(
				bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, off, length)
			if err != nil {
				t.Fatalf("NewDecryptRangeReader(off=%d, length=%d): %v", off, length, err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll(off=%d, length=%d): %v", off, length, err)
			}
			if want := plaintext[off : off+length]; !bytes.Equal(got, want) {
				t.Fatalf("range [%d,%d) disagreed with a full decrypt", off, off+length)
			}
		}
	})

	t.Run("RangedReadRefusesABadRange", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		plaintext := patterned(200)
		ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)
		size := int64(len(ciphertext))

		cases := map[string][2]int64{
			"negative offset": {-1, 10},
			"negative length": {0, -1},
			"past the end":    {100, 200},
			// off and length arrive from an HTTP Range header in practice, so
			// a pair that overflows int64 when added must be refused rather
			// than wrap into an allocation.
			"overflowing when added": {1 << 62, 1 << 62},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := s.NewDecryptRangeReader(
					bytes.NewReader(ciphertext), size, dek, addr, c[0], c[1],
				); !errors.Is(err, seal.ErrRange) {
					t.Fatalf("off=%d length=%d: err = %v, want ErrRange", c[0], c[1], err)
				}
			})
		}
	})

	// Close is what stops a short read silently suppressing a later
	// authentication failure, so a caller that reads a prefix and closes must
	// still learn that the tail is corrupt.
	t.Run("CloseAuthenticatesWhatTheCallerDidNotRead", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		plaintext := patterned(2 * seal.FrameSize)
		ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)

		// Corrupt the last byte, which no prefix read will reach.
		ciphertext[len(ciphertext)-1] ^= 0x01

		r, err := s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, seal.Unlimited)
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		if _, err := r.Read(make([]byte, 10)); err != nil {
			t.Fatalf("Read of the first bytes: err = %v, want nil (the corruption is at the end)", err)
		}
		if err := r.Close(); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("Close after a short read of a tail-corrupt object: err = %v, want ErrCorrupt", err)
		}
	})

	// The other half of the one above, and not redundant with it: a Close that
	// drains the rest of a *clean* object must return nil. Without this, an
	// implementation that satisfied the previous subtest by returning
	// ErrCorrupt from every Close after a partial read would pass — and a
	// caller that correctly checks Close's error would then see every
	// abandoned download as a corrupt object.
	t.Run("CloseOfACleanObjectAfterAPartialReadReturnsNil", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(2*seal.FrameSize))

		r, err := s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, seal.Unlimited)
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		if _, err := r.Read(make([]byte, 10)); err != nil {
			t.Fatalf("Read of the first bytes: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("Close after a short read of a clean object: err = %v, want nil", err)
		}
	})

	// A write after Close must be refused rather than silently appended to a
	// stream whose final frame is already sealed — which would produce a
	// ciphertext that is longer than the object it claims to hold and that no
	// reader can open. The record suite asserts the same thing for its writer;
	// the stream writer's half lived only in internal/framed.
	t.Run("RefusesAWriteAfterClose", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)

		var buf bytes.Buffer
		w, err := s.NewEncryptWriter(&buf, dek, addr)
		if err != nil {
			t.Fatalf("NewEncryptWriter: %v", err)
		}
		if _, err := w.Write([]byte("the object's only bytes")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		sealed := buf.Len()

		if _, err := w.Write([]byte("more")); !errors.Is(err, seal.ErrClosed) {
			t.Errorf("Write after Close: err = %v, want ErrClosed", err)
		}
		if buf.Len() != sealed {
			t.Errorf("the writer appended %d bytes after Close; the stream's final frame was already sealed",
				buf.Len()-sealed)
		}
	})

	t.Run("RefusesPlaintextOverTheCeiling", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)

		out, err := s.EncryptObject(dek, addr, patterned(65), seal.Limits{MaxPlaintext: 64})
		assertLimitRefusal(t, "EncryptObject", "max plaintext", 64, err, out)
	})

	t.Run("RefusesCiphertextOverTheCeiling", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(4096))

		out, err := s.DecryptObject(dek, addr, ciphertext, seal.Limits{
			MaxPlaintext:  seal.Unlimited,
			MaxCiphertext: 1024,
		})
		assertLimitRefusal(t, "DecryptObject", "max ciphertext", 1024, err, out)
	})

	t.Run("EnforcesThePlaintextCeilingOnDecryptToo", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(4096))

		out, err := s.DecryptObject(dek, addr, ciphertext, seal.Limits{
			MaxPlaintext:  1024,
			MaxCiphertext: seal.Unlimited,
		})
		assertLimitRefusal(t, "DecryptObject", "max plaintext", 1024, err, out)
	})

	// CHARTER.md's fifth ceiling rule. Streaming bounds the implementation's
	// memory to one frame; it does not bound the caller's, so the reader takes
	// a total plaintext ceiling — and a zero is refused rather than quietly
	// meaning unbounded.
	t.Run("StreamingIsNotExemptFromItsCeiling", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		plaintext := patterned(4096)
		ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)

		r, err := s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, 1024)
		if err != nil {
			t.Fatalf("NewDecryptReader with a 1024-byte ceiling: %v", err)
		}
		got, err := io.ReadAll(r)
		if !errors.Is(err, seal.ErrLimitExceeded) {
			t.Fatalf("ReadAll of a 4096-byte stream under a 1024-byte ceiling: err = %v, want ErrLimitExceeded", err)
		}
		if int64(len(got)) > 1024 {
			t.Errorf("the reader handed back %d bytes before refusing, past its 1024-byte ceiling", len(got))
		}

		if _, err := s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, 0); !errors.Is(err, seal.ErrInvalidLimit) {
			t.Fatalf("NewDecryptReader with a zero ceiling: err = %v, want ErrInvalidLimit", err)
		}
	})

	// The rendering discipline, by name, so no implementation can quietly skip
	// it. Both halves are run: the negative one against the DEK, which is the
	// one material-bearing value crossing this boundary, and the positive one
	// against the three values this port hands back, whose whole contents are
	// a derived key schedule and a plaintext buffer.
	t.Run("RedactsEveryValueItHandsBack", func(t *testing.T) {
		s := newSealer(t)
		_, addr := streamFixture(t)

		dek, err := keyring.DEKFrom(knownMaterial)
		if err != nil {
			t.Fatalf("keyring.DEKFrom(knownMaterial): %v", err)
		}
		defer dek.Destroy()
		NoSecretLeaksInAnyRendering(t, dek, knownMaterial)

		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(200))
		w, err := s.NewEncryptWriter(io.Discard, dek, addr)
		if err != nil {
			t.Fatalf("NewEncryptWriter: %v", err)
		}
		dr, err := s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, seal.Unlimited)
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		rr, err := s.NewDecryptRangeReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, 0, 10)
		if err != nil {
			t.Fatalf("NewDecryptRangeReader: %v", err)
		}
		for _, v := range []any{w, dr, rr} {
			RendersOnlyARedactionMarker(t, v)
		}
	})

	// The other half of the leak discipline, and the half nothing here reached
	// before: a failure path's *error*. The subtest above holds the writer and
	// the readers to what they print; an error is a different string, built on
	// a different path, and the one a caller is most likely to log verbatim.
	// See errleaks.go.
	runStreamErrorCanary(t, newSealer)
}

// RunRecordSealerSuite runs the contract every seal.RecordSealer
// implementation must satisfy. newSealer is called once per subtest with that
// subtest's own *T; see RunStreamSealerSuite.
func RunRecordSealerSuite(t *testing.T, newSealer func(t *testing.T) seal.RecordSealer) {
	t.Helper()

	t.Run("RoundTripsAcrossSizes", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)

		for _, size := range []int{0, 1, 20, 1024, 65536, int(seal.DefaultMaxPlaintext)} {
			t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
				plaintext := patterned(size)
				record, err := s.EncryptRecord(dek, addr, plaintext, seal.Limits{})
				if err != nil {
					t.Fatalf("EncryptRecord: %v", err)
				}
				got, err := s.DecryptRecord(dek, addr, record, seal.Limits{})
				if err != nil {
					t.Fatalf("DecryptRecord: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("round trip mismatch at %d bytes", size)
				}
			})
		}
	})

	t.Run("DetectsAFlippedBitAnywhere", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record := mustEncryptRecord(t, s, dek, addr, patterned(64))

		for i := range record {
			tampered := append([]byte{}, record...)
			tampered[i] ^= 0x01
			if _, err := s.DecryptRecord(dek, addr, tampered, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
				t.Errorf("byte %d of %d flipped: err = %v, want ErrCorrupt", i, len(record), err)
			}
		}
	})

	t.Run("DetectsEveryTruncation", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record := mustEncryptRecord(t, s, dek, addr, patterned(64))

		for n := 0; n < len(record); n++ {
			if _, err := s.DecryptRecord(dek, addr, record[:n], seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
				t.Errorf("truncated to %d of %d bytes: err = %v, want ErrCorrupt", n, len(record), err)
			}
		}
	})

	// The module's central claim for small values, and leak channel #17 in the
	// kgs design: a value relocated onto another row must be a decryption
	// failure, not a silent wrong answer. Every component is varied
	// independently, because a binding that covers two of three lets the third
	// be rewritten.
	t.Run("RefusesRelocationToAnotherAddress", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record := mustEncryptRecord(t, s, dek, addr, []byte("147500 EUR per year"))

		for name, parts := range map[string][]string{
			"another graph":             {"graph-2", "fact-1", "salary"},
			"another fact in the graph": {"graph-1", "fact-2", "salary"},
			"another attribute":         {"graph-1", "fact-1", "bonus"},
			"a shorter address":         {"graph-1", "fact-1"},
			"a longer address":          {"graph-1", "fact-1", "salary", "v2"},
			"the same parts reordered":  {"salary", "fact-1", "graph-1"},
		} {
			t.Run(name, func(t *testing.T) {
				wrong, err := seal.NewRecordAddress(parts...)
				if err != nil {
					t.Fatalf("NewRecordAddress: %v", err)
				}
				if _, err := s.DecryptRecord(dek, wrong, record, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
					t.Fatalf("opened at %s: err = %v, want ErrCorrupt", name, err)
				}
			})
		}
	})

	t.Run("RefusesAnotherDEK", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record := mustEncryptRecord(t, s, dek, addr, patterned(64))

		other, err := keyring.NewDEK()
		if err != nil {
			t.Fatalf("keyring.NewDEK: %v", err)
		}
		defer other.Destroy()
		if _, err := s.DecryptRecord(other, addr, record, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("opened under another DEK: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("RefusesADEKThatHoldsNoMaterial", func(t *testing.T) {
		s := newSealer(t)
		_, addr := recordFixture(t)

		destroyed, err := keyring.NewDEK()
		if err != nil {
			t.Fatalf("keyring.NewDEK: %v", err)
		}
		destroyed.Destroy()

		for name, dek := range map[string]seal.DEK{"zero value": {}, "destroyed": destroyed} {
			t.Run(name, func(t *testing.T) {
				if _, err := s.EncryptRecord(dek, addr, []byte("v"), seal.Limits{}); !errors.Is(err, seal.ErrInvalidDEK) {
					t.Errorf("EncryptRecord: err = %v, want ErrInvalidDEK", err)
				}
			})
		}
	})

	// The nonce-management claim made testable. The per-record key is only per
	// record if the salt actually varies, and a format that produced identical
	// ciphertext for identical input would also leak which rows hold the same
	// value — which for an attribute like a diagnosis or a salary band is most
	// of what an attacker wanted.
	//
	// The record count is a runtime decision, never a build tag: the inner
	// loop samples the property and the full run sweeps it.
	t.Run("DrawsFreshRandomnessPerRecord", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)

		records := 50_000
		if testing.Short() {
			records = 200
		}
		seen := make(map[string]struct{}, records)
		plaintext := []byte("the same value every time")
		for i := 0; i < records; i++ {
			record, err := s.EncryptRecord(dek, addr, plaintext, seal.Limits{})
			if err != nil {
				t.Fatalf("EncryptRecord %d: %v", i, err)
			}
			if _, dup := seen[string(record)]; dup {
				t.Fatalf("two of %d records with identical input produced identical ciphertext: "+
					"the per-record key is not per-record, and equality of values is observable", records)
			}
			seen[string(record)] = struct{}{}
		}
	})

	t.Run("RefusesPlaintextOverTheCeiling", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)

		out, err := s.EncryptRecord(dek, addr, patterned(65), seal.Limits{MaxPlaintext: 64})
		assertLimitRefusal(t, "EncryptRecord", "max plaintext", 64, err, out)
	})

	// Rule 1's point: the two ceilings bound different things on different
	// sides of the trust boundary, and only a pair can express "generous on
	// the way in, strict on the way out".
	t.Run("RefusesCiphertextOverTheCeiling", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record, err := s.EncryptRecord(dek, addr, patterned(4096), seal.Limits{MaxPlaintext: seal.Unlimited})
		if err != nil {
			t.Fatalf("EncryptRecord: %v", err)
		}

		out, err := s.DecryptRecord(dek, addr, record, seal.Limits{
			MaxPlaintext:  seal.Unlimited,
			MaxCiphertext: 1024,
		})
		assertLimitRefusal(t, "DecryptRecord", "max ciphertext", 1024, err, out)
	})

	// The asymmetry a caller can create by hand and would not expect to be a
	// hole: MaxCiphertext opted out explicitly, with MaxPlaintext left in
	// place. The derived default normally makes the two agree, so this only
	// arises deliberately — and reading it as "no bound on either" would be
	// the surprising answer rather than the safe one.
	t.Run("EnforcesThePlaintextCeilingOnDecryptToo", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record, err := s.EncryptRecord(dek, addr, patterned(4096), seal.Limits{MaxPlaintext: seal.Unlimited})
		if err != nil {
			t.Fatalf("EncryptRecord: %v", err)
		}

		out, err := s.DecryptRecord(dek, addr, record, seal.Limits{
			MaxPlaintext:  1024,
			MaxCiphertext: seal.Unlimited,
		})
		assertLimitRefusal(t, "DecryptRecord", "max plaintext", 1024, err, out)
	})

	t.Run("RefusesANonsensicalCeiling", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)

		for name, limits := range map[string]seal.Limits{
			"negative plaintext ceiling":  {MaxPlaintext: -2},
			"negative ciphertext ceiling": {MaxCiphertext: -7},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := s.EncryptRecord(dek, addr, []byte("v"), limits); !errors.Is(err, seal.ErrInvalidLimit) {
					t.Fatalf("EncryptRecord: err = %v, want ErrInvalidLimit", err)
				}
			})
		}
	})

	// CHARTER.md's third ceiling rule, and it is the one an implementation is
	// most likely to get wrong by being helpful: with a ceiling configured and
	// no way to establish the input's length up front, the operation is
	// refused rather than read until the ceiling is hit.
	t.Run("FailsClosedOnAnUnknownLength", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		record := mustEncryptRecord(t, s, dek, addr, []byte("value"))

		// A *bytes.Reader declares its length through Len, so it is accepted.
		if _, err := s.NewRecordReader(bytes.NewReader(record), dek, addr, seal.Limits{}); err != nil {
			t.Fatalf("NewRecordReader over a reader that declares its length: %v", err)
		}

		// An opaque reader cannot, so with a ceiling in force it is refused.
		if _, err := s.NewRecordReader(opaqueReader(record), dek, addr, seal.Limits{}); !errors.Is(err, seal.ErrUnknownLength) {
			t.Fatalf("NewRecordReader over a reader with no declarable length: err = %v, want ErrUnknownLength", err)
		}

		// With no ceiling there is nothing an unknown length could exceed, so
		// the same reader is accepted: fail-closed, not fail-always.
		r, err := s.NewRecordReader(opaqueReader(record), dek, addr, seal.Limits{
			MaxPlaintext:  seal.Unlimited,
			MaxCiphertext: seal.Unlimited,
		})
		if err != nil {
			t.Fatalf("NewRecordReader over the same reader with no ceiling: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, []byte("value")) {
			t.Fatalf("unbounded read returned %q", got)
		}
	})

	t.Run("StreamingShapesRoundTrip", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := recordFixture(t)
		plaintext := []byte("a value arriving as a stream of writes")

		var buf bytes.Buffer
		w, err := s.NewRecordWriter(&buf, dek, addr, seal.Limits{})
		if err != nil {
			t.Fatalf("NewRecordWriter: %v", err)
		}
		for _, chunk := range bytes.SplitAfter(plaintext, []byte(" ")) {
			if _, err := w.Write(chunk); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := w.Write([]byte("more")); !errors.Is(err, seal.ErrClosed) {
			t.Errorf("Write after Close: err = %v, want ErrClosed", err)
		}

		r, err := s.NewRecordReader(bytes.NewReader(buf.Bytes()), dek, addr, seal.Limits{})
		if err != nil {
			t.Fatalf("NewRecordReader: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("streaming round trip mismatch")
		}
	})

	t.Run("RedactsEveryValueItHandsBack", func(t *testing.T) {
		s := newSealer(t)
		_, addr := recordFixture(t)

		dek, err := keyring.DEKFrom(knownMaterial)
		if err != nil {
			t.Fatalf("keyring.DEKFrom(knownMaterial): %v", err)
		}
		defer dek.Destroy()
		NoSecretLeaksInAnyRendering(t, dek, knownMaterial)

		var buf bytes.Buffer
		w, err := s.NewRecordWriter(&buf, dek, addr, seal.Limits{})
		if err != nil {
			t.Fatalf("NewRecordWriter: %v", err)
		}
		if _, err := w.Write(knownMaterial); err != nil {
			t.Fatalf("Write: %v", err)
		}
		// Rendered while the writer still holds the plaintext.
		RendersOnlyARedactionMarker(t, w)
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		r, err := s.NewRecordReader(bytes.NewReader(buf.Bytes()), dek, addr, seal.Limits{})
		if err != nil {
			t.Fatalf("NewRecordReader: %v", err)
		}
		RendersOnlyARedactionMarker(t, r)
	})

	// See runStreamErrorCanary and errleaks.go: the rendering subtest above
	// says nothing about an error's contents.
	runRecordErrorCanary(t, newSealer)
}

// NewDEK returns a fresh DEK for a test, destroyed when t and every subtest
// under it have finished.
//
// It exists because seal's public API has no DEK constructor and deliberately
// will not get one. Generating, wrapping, storing and destroying key material
// is keyring's whole subject and CHARTER.md disclaims all of it, so a
// seal.NewDEK would advertise a capability this module must never own — and a
// caller that reached for it would end up with a key it has nowhere to put. A
// consumer encrypting in production gets its DEK from keyring's key manager
// (UnwrapDEK) and therefore requires keyring directly, which is correct and
// intended.
//
// What that left without an answer is the *test*. CAS found it on adoption
// day: a module whose production code only runs the conformance suites needs
// no direct keyring require, because the suites build their own DEKs — but the
// moment it writes one test of its own against seal it needs keyring in its
// main require block, and CAS had it direct for exactly one commit before
// going back to `// indirect`. A test fixture belongs in the test-support
// package, which already depends on keyring, rather than in the production
// API. So it is here.
//
// The returned DEK holds real random material: this is a fixture, not a
// stub, and a test that encrypts under a predictable key proves less than it
// appears to. For a DEK whose material a test must *name* — a leak canary's
// needle — use keyring.DEKFrom, which is keyring's to provide.
func NewDEK(t *testing.T) seal.DEK {
	t.Helper()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("keyring.NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	return dek
}

// streamFixture returns a fresh DEK, destroyed when the subtest ends, and the
// address every stream subtest binds to.
func streamFixture(t *testing.T) (seal.DEK, seal.ObjectAddress) {
	t.Helper()
	dek := NewDEK(t)
	addr, err := seal.NewObjectAddress("tenant-1", "sha256:"+hexRepeat("ab", 32))
	if err != nil {
		t.Fatalf("NewObjectAddress: %v", err)
	}
	return dek, addr
}

// recordFixture returns a fresh DEK, destroyed when the subtest ends, and the
// three-component address every record subtest binds to.
func recordFixture(t *testing.T) (seal.DEK, seal.RecordAddress) {
	t.Helper()
	dek := NewDEK(t)
	addr, err := seal.NewRecordAddress("graph-1", "fact-1", "salary")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	return dek, addr
}

func mustEncryptObject(
	t *testing.T, s seal.StreamSealer, dek seal.DEK, addr seal.ObjectAddress, plaintext []byte,
) []byte {
	t.Helper()
	out, err := s.EncryptObject(dek, addr, plaintext, seal.Limits{MaxPlaintext: seal.Unlimited})
	if err != nil {
		t.Fatalf("EncryptObject(%d bytes): %v", len(plaintext), err)
	}
	return out
}

func mustEncryptRecord(
	t *testing.T, s seal.RecordSealer, dek seal.DEK, addr seal.RecordAddress, plaintext []byte,
) []byte {
	t.Helper()
	out, err := s.EncryptRecord(dek, addr, plaintext, seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptRecord(%d bytes): %v", len(plaintext), err)
	}
	return out
}

// assertLimitRefusal holds one ceiling refusal to all of CHARTER.md's fourth
// rule: a typed error that names the limit, matching the sentinel, and no
// result at all alongside it.
func assertLimitRefusal(t *testing.T, call, wantLimit string, wantMax int64, err error, out []byte) {
	t.Helper()
	if !errors.Is(err, seal.ErrLimitExceeded) {
		t.Fatalf("%s over its ceiling: err = %v, want ErrLimitExceeded", call, err)
	}
	var limitErr *seal.LimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("%s: err = %v, want a *seal.LimitError that names the ceiling", call, err)
	}
	if limitErr.Limit != wantLimit {
		t.Errorf("%s: LimitError.Limit = %q, want %q", call, limitErr.Limit, wantLimit)
	}
	if limitErr.Max != wantMax {
		t.Errorf("%s: LimitError.Max = %d, want %d", call, limitErr.Max, wantMax)
	}
	if out != nil {
		t.Errorf("%s returned %d bytes alongside its refusal; a refusal must never carry a partial result",
			call, len(out))
	}
}

// opaqueReader wraps b in a reader with no Len, no Stat and no Seek, so a
// ceiling-bearing entry point cannot establish its length. This is what an
// HTTP body, a network connection or a pipe looks like to the length probe.
func opaqueReader(b []byte) io.Reader {
	return struct{ io.Reader }{bytes.NewReader(b)}
}

// patterned returns n deterministic, non-repeating-looking bytes. Fixed rather
// than random so that a failure is reproducible from the test name alone.
func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

// hexRepeat returns pair repeated to produce count bytes' worth of hex, which
// is how the fixtures spell a content address's hex half.
func hexRepeat(pair string, count int) string {
	out := make([]byte, 0, len(pair)*count)
	for i := 0; i < count; i++ {
		out = append(out, pair...)
	}
	return string(out)
}
