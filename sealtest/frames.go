package sealtest

// This file holds the part of the StreamSealer contract that needs more than
// one frame, and the measurement that makes it reachable from outside this
// module.
//
// Why it exists at all: every tamper sweep in suite.go encrypts 200 bytes
// against a 1 MiB seal.FrameSize, so every one of them sweeps a *single-frame*
// stream. Sweeping every truncation of one frame does not subsume "the
// stream's final frame was dropped", because there is no second frame to drop;
// sweeping every bit of one frame never moves a frame within a stream, so the
// frame-index binding — the property that stops two frames being swapped or an
// interior one being removed — was not exercised by any consumer at all. It
// was tested only in internal/framed, which nothing outside this module can
// import. CAS measured that when it adopted seal v0.1.0 and found three of the
// eleven suites it could reach weaker than their names suggested.
//
// # Why the geometry is measured and not assumed
//
// Positioning a frame boundary needs to know where frames start and how long
// they are, and suite.go's standing rule is that nothing inspects the wire
// format: a suite that hardcodes a 25-byte header and a 16-byte tag passes for
// exactly one implementation. So the geometry is *measured* from the
// implementation under test, through its own entry points, by encrypting three
// plaintexts of known length and solving for the two unknowns. What that
// assumes is only the framed family's affine wire shape — a fixed prologue,
// then one constant-overhead frame per seal.FrameSize of plaintext — which
// docs/format.md fixes for format version 1 and which the measurement then
// re-derives and checks against a fourth, multi-frame length. An
// implementation whose geometry does not hold up fails the measurement by
// name, with the four numbers it produced, rather than failing a tamper
// assertion for a reason nobody can read.
//
// # Why the sweeps here are sampled and the ones in suite.go are exhaustive
//
// seal.FrameSize is 1 MiB, so the smallest interesting multi-frame fixture is
// just over 2 MiB and its ciphertext is 2,098,459 bytes. A bit flip at every
// byte position of that is two million decrypt attempts of a two-megabyte
// stream — comfortably twenty minutes — and every truncation of it is another
// two million. The exhaustive versions in suite.go are affordable only because
// their fixture is 200 bytes.
//
// So these sweeps sample deliberately, at the positions where a framing bug
// actually lives: every byte of the prologue, and per frame its first and last
// body byte, its first and last tag byte, and a few interior offsets. The
// interior samples are what -short drops; the structural ones always run,
// because they are the sweep's whole value and they are cheap.
//
// **Do not "fix" this into an exhaustive sweep.** The three named properties
// below — a dropped final frame, a dropped interior frame, two swapped frames
// — are not reached by sampling harder, and an exhaustive version of either
// loop would be a twenty-minute test that nobody runs and that therefore
// protects nothing.

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/laenenai/seal"
)

// multiFramePlaintext is the plaintext size every subtest in this file uses:
// three frames, of which the first two are full and equal length — so they can
// be swapped without changing the stream's total length — and the third is
// short, so dropping it is distinguishable from dropping a full one. It is the
// same size suite.go's RangedReadMatchesFullDecrypt already uses.
const multiFramePlaintext = 2*seal.FrameSize + 1234

// runMultiFrameSubtests registers the parts of the StreamSealer contract that
// need more than one frame. It is called from RunStreamSealerSuite, and takes
// the factory rather than a sealer so that each subtest gets its own, which is
// the suite's standing convention.
func runMultiFrameSubtests(t *testing.T, newSealer func(t *testing.T) seal.StreamSealer) {
	t.Helper()

	// A security property, and the one a consumer could not reach at all
	// before: the final frame of a multi-frame stream is removed, which is
	// what a storage layer that lost its last write looks like. suite.go's
	// exhaustive truncation sweep cannot subsume this, because its fixture has
	// only one frame.
	t.Run("DetectsADroppedFinalFrame", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		g := measureFramedGeometry(t, s, dek, addr)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(multiFramePlaintext))

		truncated := ciphertext[:g.offsetOfFrame(g.frames-1)]
		if _, err := s.DecryptObject(dek, addr, truncated, seal.Limits{MaxPlaintext: seal.Unlimited}); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("decrypt of a %d-frame stream with its final frame removed (%d of %d bytes left): err = %v, want ErrCorrupt",
				g.frames, len(truncated), len(ciphertext), err)
		}
	})

	// A security property, and the frame-index binding's first half: a frame
	// removed from the middle of a stream shifts every later frame into an
	// index it was not sealed under.
	t.Run("DetectsADroppedInteriorFrame", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		g := measureFramedGeometry(t, s, dek, addr)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(multiFramePlaintext))

		start, end := g.offsetOfFrame(1), g.offsetOfFrame(2)
		tampered := make([]byte, 0, len(ciphertext)-(end-start))
		tampered = append(tampered, ciphertext[:start]...)
		tampered = append(tampered, ciphertext[end:]...)

		if _, err := s.DecryptObject(dek, addr, tampered, seal.Limits{MaxPlaintext: seal.Unlimited}); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("decrypt of a %d-frame stream with frame 1 removed: err = %v, want ErrCorrupt", g.frames, err)
		}
	})

	// A security property, and the frame-index binding's other half. The two
	// frames swapped are both full and equal length, so the stream's total
	// length, its frame count and its finality structure are all unchanged —
	// nothing but the index binding can detect this, which is exactly why it
	// is worth a subtest of its own rather than being left to a bit-flip
	// sweep.
	t.Run("DetectsTwoSwappedFrames", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		g := measureFramedGeometry(t, s, dek, addr)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(multiFramePlaintext))

		tampered := append([]byte{}, ciphertext...)
		first := tampered[g.offsetOfFrame(0):g.offsetOfFrame(1)]
		second := tampered[g.offsetOfFrame(1):g.offsetOfFrame(2)]
		if len(first) != len(second) {
			t.Fatalf("frames 0 and 1 are %d and %d wire bytes; this subtest needs two equal-length full frames",
				len(first), len(second))
		}
		scratch := append([]byte{}, first...)
		copy(first, second)
		copy(second, scratch)

		if _, err := s.DecryptObject(dek, addr, tampered, seal.Limits{MaxPlaintext: seal.Unlimited}); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("decrypt of a %d-frame stream with frames 0 and 1 swapped: err = %v, want ErrCorrupt", g.frames, err)
		}
	})

	// A security property. Sampled, not exhaustive — see this file's header
	// comment for the arithmetic. The positions are chosen where a framing bug
	// lives rather than uniformly: the whole prologue, and each frame's first
	// and last body byte, first and last tag byte, and a few interior offsets.
	t.Run("DetectsAFlippedBitInAMultiFrameStream", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		g := measureFramedGeometry(t, s, dek, addr)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(multiFramePlaintext))

		for _, i := range g.flipPositions(len(ciphertext)) {
			tampered := append([]byte{}, ciphertext...)
			tampered[i] ^= 0x01
			if _, err := s.DecryptObject(dek, addr, tampered, seal.Limits{MaxPlaintext: seal.Unlimited}); !errors.Is(err, seal.ErrCorrupt) {
				t.Errorf("byte %d of %d flipped (%s): err = %v, want ErrCorrupt",
					i, len(ciphertext), g.describe(i, len(ciphertext)), err)
			}
		}
	})

	// A security property. Sampled for the same reason as the flip sweep, and
	// at the lengths where framing arithmetic goes wrong: on, just before and
	// just after every frame boundary, plus the prologue's edges and a point
	// inside each frame.
	t.Run("DetectsATruncatedMultiFrameStream", func(t *testing.T) {
		s := newSealer(t)
		dek, addr := streamFixture(t)
		g := measureFramedGeometry(t, s, dek, addr)
		ciphertext := mustEncryptObject(t, s, dek, addr, patterned(multiFramePlaintext))

		for _, n := range g.truncationLengths(len(ciphertext)) {
			if _, err := s.DecryptObject(dek, addr, ciphertext[:n], seal.Limits{MaxPlaintext: seal.Unlimited}); !errors.Is(err, seal.ErrCorrupt) {
				t.Errorf("truncated to %d of %d bytes (%s): err = %v, want ErrCorrupt",
					n, len(ciphertext), g.describe(n, len(ciphertext)), err)
			}
		}
	})
}

// framedGeometry is a framed stream's wire geometry as the implementation
// under test actually produces it: a fixed prologue, then one frame per
// seal.FrameSize of plaintext, each costing a constant overhead.
//
// Only the two unknowns are measured. frameSize is not: it is seal.FrameSize,
// which is what the port's own documentation says an encoder writes, and an
// implementation that framed at some other size would fail the consistency
// check in measureFramedGeometry rather than be quietly accommodated.
type framedGeometry struct {
	// prologue is the number of wire bytes before the first frame.
	prologue int
	// overhead is one frame's constant wire cost beyond its plaintext.
	overhead int
	// frames is how many frames multiFramePlaintext bytes occupy.
	frames int
	// finalPlaintext is the last frame's plaintext length.
	finalPlaintext int
}

// stride is a full frame's wire length.
func (g framedGeometry) stride() int { return seal.FrameSize + g.overhead }

// offsetOfFrame returns the wire offset at which frame i begins. i may equal
// g.frames, which yields the stream's total length.
func (g framedGeometry) offsetOfFrame(i int) int { return g.prologue + i*g.stride() }

// wireLenOfFrame returns frame i's wire length, which differs for the last
// frame whenever the plaintext is not an exact multiple of seal.FrameSize.
func (g framedGeometry) wireLenOfFrame(i int) int {
	if i == g.frames-1 {
		return g.finalPlaintext + g.overhead
	}
	return g.stride()
}

// measureFramedGeometry derives the wire geometry of s by encrypting four
// plaintexts of known length and solving for the prologue and the per-frame
// overhead.
//
// With P the prologue, V the per-frame overhead and F = seal.FrameSize:
//
//	len(ciphertext of 0 bytes)   = P + V            (one empty final frame)
//	len(ciphertext of F bytes)   = P + F + V        (one full final frame)
//	len(ciphertext of F+1 bytes) = P + F + 1 + 2V   (a full frame, then one byte)
//
// so V is the third minus the second minus one, and P is the first minus V.
// The second equation is then an independent check rather than an input, and a
// fourth encryption at multiFramePlaintext checks the whole model at the size
// the subtests actually tamper with.
//
// The cost is four encryptions — about 4 MiB of AEAD — per subtest that needs
// the geometry, paid rather than cached so that every subtest still gets its
// own sealer from its own factory call, which is this suite's convention.
func measureFramedGeometry(t *testing.T, s seal.StreamSealer, dek seal.DEK, addr seal.ObjectAddress) framedGeometry {
	t.Helper()

	empty := len(mustEncryptObject(t, s, dek, addr, nil))
	oneFrame := len(mustEncryptObject(t, s, dek, addr, patterned(seal.FrameSize)))
	oneFramePlusAByte := len(mustEncryptObject(t, s, dek, addr, patterned(seal.FrameSize+1)))

	g := framedGeometry{
		overhead:       oneFramePlusAByte - oneFrame - 1,
		frames:         (multiFramePlaintext + seal.FrameSize - 1) / seal.FrameSize,
		finalPlaintext: multiFramePlaintext % seal.FrameSize,
	}
	g.prologue = empty - g.overhead

	if g.overhead <= 0 || g.prologue < 0 {
		t.Fatalf("measured a prologue of %d bytes and a per-frame overhead of %d from ciphertext lengths "+
			"%d (empty), %d (one frame) and %d (one frame plus a byte): this implementation's wire shape is "+
			"not the framed family's fixed prologue plus constant-overhead frames, so a frame boundary cannot "+
			"be positioned and the frame-level properties below cannot be asserted",
			g.prologue, g.overhead, empty, oneFrame, oneFramePlusAByte)
	}
	if want := g.prologue + seal.FrameSize + g.overhead; oneFrame != want {
		t.Fatalf("a one-frame stream is %d wire bytes, but a prologue of %d and an overhead of %d predict %d",
			oneFrame, g.prologue, g.overhead, want)
	}
	if got, want := len(mustEncryptObject(t, s, dek, addr, patterned(multiFramePlaintext))),
		g.offsetOfFrame(g.frames-1)+g.wireLenOfFrame(g.frames-1); got != want {
		t.Fatalf("a %d-byte plaintext is %d wire bytes, but a prologue of %d and an overhead of %d over %d frames "+
			"predict %d: the measured geometry does not hold at the size these subtests tamper with",
			multiFramePlaintext, got, g.prologue, g.overhead, g.frames, want)
	}
	return g
}

// flipPositions returns the byte positions the flip sweep samples, sorted and
// without duplicates. Every byte of the prologue is included because it is
// small and because the header is the one region whose authentication is
// indirect — it carries no tag of its own and is covered only by being bound
// into every frame's AAD.
func (g framedGeometry) flipPositions(total int) []int {
	var positions []int
	for i := 0; i < g.prologue; i++ {
		positions = append(positions, i)
	}
	for f := 0; f < g.frames; f++ {
		start := g.offsetOfFrame(f)
		wire := g.wireLenOfFrame(f)
		body := wire - g.overhead
		// The body's first and last byte, then the overhead's — which for an
		// AEAD frame is its tag, the bytes a sweep that only touched
		// ciphertext would miss.
		positions = append(positions, start, start+wire-g.overhead, start+wire-1)
		if body > 0 {
			positions = append(positions, start+body-1)
		}
		if !testing.Short() {
			for _, fraction := range []int{4, 2} {
				if body > fraction {
					positions = append(positions, start+body/fraction)
				}
			}
		}
	}
	return clamped(positions, total)
}

// truncationLengths returns the lengths the truncation sweep samples. A
// truncation to exactly offsetOfFrame(frames-1) is the dropped final frame,
// which DetectsADroppedFinalFrame also asserts on its own so that the property
// has a name in test output rather than only a position in a loop.
func (g framedGeometry) truncationLengths(total int) []int {
	positions := []int{0, 1, g.prologue - 1, g.prologue, g.prologue + 1, total - 1}
	for f := 0; f < g.frames; f++ {
		start := g.offsetOfFrame(f)
		positions = append(positions, start-1, start, start+1)
		if !testing.Short() {
			positions = append(positions, start+g.wireLenOfFrame(f)/2)
		}
	}
	return clamped(positions, total)
}

// clamped sorts positions, drops duplicates and drops anything outside
// [0, total). It builds a new slice rather than filtering in place: an
// in-place filter would overwrite the element the duplicate check compares
// against.
func clamped(positions []int, total int) []int {
	sort.Ints(positions)
	out := make([]int, 0, len(positions))
	for i, p := range positions {
		if p < 0 || p >= total {
			continue
		}
		if i > 0 && p == positions[i-1] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// describe names the region a wire offset falls in, so a failure message says
// "frame 1's tag" rather than only a number.
func (g framedGeometry) describe(off, total int) string {
	switch {
	case off < g.prologue:
		return fmt.Sprintf("the %d-byte prologue", g.prologue)
	case off >= total:
		return "past the end of the stream"
	}
	f := (off - g.prologue) / g.stride()
	if f >= g.frames {
		f = g.frames - 1
	}
	within := off - g.offsetOfFrame(f)
	if within >= g.wireLenOfFrame(f)-g.overhead {
		return fmt.Sprintf("frame %d of %d, in its %d-byte overhead", f, g.frames, g.overhead)
	}
	return fmt.Sprintf("frame %d of %d, byte %d of its body", f, g.frames, within)
}
