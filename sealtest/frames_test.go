package sealtest

// The self-test for frames.go. Two things need pinning, and neither is pinned
// by the conformance subtests themselves.
//
// First, that the measurement is right rather than merely self-consistent. A
// measurement that solved for the wrong pair of numbers and then checked its
// own prediction would agree with itself; these tests check it against the
// numbers docs/format.md states for format version 1 — a 25-byte header and a
// 16-byte GCM tag.
//
// Second, that the sweeps stay samples. frames.go's header comment asks the
// next reader not to turn them into exhaustive loops, and a comment is not an
// enforcement mechanism: TestFlipPositions_StayASample fails if the sample
// grows past a bound no sampled sweep needs, which is what an exhaustive
// rewrite looks like from here.

import (
	"bytes"
	"testing"

	"github.com/laenenai/seal"
)

// framedHeaderLen and framedTagLen are what docs/format.md states for format
// version 1. They are duplicated here on purpose: internal/domain is not
// importable from this package, and the point of the test is to compare the
// measurement against the document rather than against the code.
const (
	framedHeaderLen = 25
	framedTagLen    = 16
)

func TestMeasureFramedGeometry_AgreesWithTheFormatDocument(t *testing.T) {
	t.Parallel()

	s := seal.Framed()
	dek, addr := streamFixture(t)
	g := measureFramedGeometry(t, s, dek, addr)

	if g.prologue != framedHeaderLen {
		t.Errorf("measured prologue = %d, want %d (docs/format.md's 25-byte header)", g.prologue, framedHeaderLen)
	}
	if g.overhead != framedTagLen {
		t.Errorf("measured per-frame overhead = %d, want %d (AES-256-GCM's tag)", g.overhead, framedTagLen)
	}
	if g.frames != 3 {
		t.Errorf("frames = %d, want 3: the fixture must have two full frames and a short final one", g.frames)
	}
	if g.finalPlaintext != 1234 {
		t.Errorf("finalPlaintext = %d, want 1234", g.finalPlaintext)
	}
	if g.wireLenOfFrame(0) != g.wireLenOfFrame(1) {
		t.Errorf("frames 0 and 1 are %d and %d wire bytes; DetectsTwoSwappedFrames needs them equal",
			g.wireLenOfFrame(0), g.wireLenOfFrame(1))
	}
}

// TestTheMultiFrameFixtureItselfRoundTrips is the control for every subtest in
// frames.go. Each of those asserts that a *tampered* stream is refused, and
// all of them would pass just as well if the untampered fixture were refused
// too — for its size, say, since it is twice the default ciphertext ceiling.
// So the untampered fixture is decrypted here, under the same Limits the
// tamper subtests use.
func TestTheMultiFrameFixtureItselfRoundTrips(t *testing.T) {
	t.Parallel()

	s := seal.Framed()
	dek, addr := streamFixture(t)
	plaintext := patterned(multiFramePlaintext)
	ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)

	got, err := s.DecryptObject(dek, addr, ciphertext, seal.Limits{MaxPlaintext: seal.Unlimited})
	if err != nil {
		t.Fatalf("DecryptObject of the untampered %d-byte fixture: %v", len(ciphertext), err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("the multi-frame fixture does not round trip, so every tamper subtest over it proves nothing")
	}
}

// maxSampledPositions is the bound that keeps a sample a sample. The sweep
// draws every prologue byte plus at most six positions per frame, so three
// frames is at most 43; anything approaching the ciphertext's two million
// bytes is an exhaustive rewrite, which frames.go's header comment explains
// must not happen.
const maxSampledPositions = 100

func TestFlipPositions_StayASample(t *testing.T) {
	t.Parallel()

	s := seal.Framed()
	dek, addr := streamFixture(t)
	g := measureFramedGeometry(t, s, dek, addr)
	total := g.offsetOfFrame(g.frames-1) + g.wireLenOfFrame(g.frames-1)

	positions := g.flipPositions(total)
	if len(positions) > maxSampledPositions {
		t.Fatalf("flipPositions returned %d of %d byte positions, past the %d a sampled sweep needs: "+
			"a bit flip at every position of a 2 MiB stream is a twenty-minute test, which is why this is sampled",
			len(positions), total, maxSampledPositions)
	}

	have := make(map[int]bool, len(positions))
	for _, p := range positions {
		have[p] = true
	}
	for i := 0; i < g.prologue; i++ {
		if !have[i] {
			t.Errorf("prologue byte %d is not sampled; the header carries no tag of its own, so every byte of "+
				"it is worth a case", i)
		}
	}
	for f := 0; f < g.frames; f++ {
		start := g.offsetOfFrame(f)
		wire := g.wireLenOfFrame(f)
		for name, p := range map[string]int{
			"its first body byte": start,
			"its last body byte":  start + wire - g.overhead - 1,
			"its first tag byte":  start + wire - g.overhead,
			"its last tag byte":   start + wire - 1,
		} {
			if !have[p] {
				t.Errorf("frame %d: %s (offset %d) is not sampled", f, name, p)
			}
		}
	}
}

func TestTruncationLengths_IncludeTheDroppedFinalFrame(t *testing.T) {
	t.Parallel()

	s := seal.Framed()
	dek, addr := streamFixture(t)
	g := measureFramedGeometry(t, s, dek, addr)
	total := g.offsetOfFrame(g.frames-1) + g.wireLenOfFrame(g.frames-1)

	lengths := g.truncationLengths(total)
	if len(lengths) > maxSampledPositions {
		t.Fatalf("truncationLengths returned %d of %d lengths, past the %d a sampled sweep needs",
			len(lengths), total, maxSampledPositions)
	}

	want := g.offsetOfFrame(g.frames - 1)
	for _, n := range lengths {
		if n == want {
			return
		}
	}
	t.Errorf("no sampled truncation length is %d, the length at which exactly the final frame is gone; "+
		"the sampled sweep is then weaker than DetectsADroppedFinalFrame rather than a superset of it", want)
}
