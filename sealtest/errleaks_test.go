package sealtest

// The self-test for the error canary, in the same spirit as redaction_test.go:
// it asserts against the detector rather than against seal's own errors, so a
// change that made the canary unable to fail is caught here rather than in six
// months when something starts leaking.

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/laenenai/seal"
)

// canaryNeedles is the needle set the canary actually uses, built once for the
// tests below.
func canaryNeedles() []needle { return errorNeedles(knownMaterial, knownPlaintext) }

// leakingWrapper is the shape that matters most and that a check of Error()
// alone would miss: a wrapper whose own message is the clean sentinel, over a
// cause that interpolated the plaintext. Anyone who logs errors.Unwrap's
// result, or whose logging library walks the chain, prints the cause.
type leakingWrapper struct{ cause error }

func (w leakingWrapper) Error() string { return "seal: corrupt ciphertext" }
func (w leakingWrapper) Unwrap() error { return w.cause }

func TestAnErrorThatInterpolatesThePlaintextIsCaught(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("decrypt object: %q: %w", knownPlaintext, seal.ErrCorrupt)
	leaks := errorLeaks(err, canaryNeedles())
	if len(leaks) == 0 {
		t.Fatal("an error holding the plaintext verbatim was reported as leaking nothing")
	}
	if !strings.Contains(leaks[0].encoding, "plaintext") {
		t.Errorf("the leak was attributed to %q rather than to the plaintext", leaks[0].encoding)
	}
}

// TestEveryEncodingOfTheKeyMaterialIsCaught pins the encodings a leak
// plausibly arrives in. A copy of this canary that dropped one would still
// pass against seal's errors, which never leak in any encoding.
func TestEveryEncodingOfTheKeyMaterialIsCaught(t *testing.T) {
	t.Parallel()

	for name, rendered := range map[string]string{
		"verbatim":      string(knownMaterial),
		"lowercase hex": hex.EncodeToString(knownMaterial),
		"uppercase hex": strings.ToUpper(hex.EncodeToString(knownMaterial)),
		"base64 (std)":  base64.StdEncoding.EncodeToString(knownMaterial),
		"base64 (url)":  base64.URLEncoding.EncodeToString(knownMaterial),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := fmt.Errorf("derive frame key from %s: %w", rendered, seal.ErrInvalidDEK)
			if leaks := errorLeaks(err, canaryNeedles()); len(leaks) == 0 {
				t.Fatalf("an error disclosing the key material as %s was reported as leaking nothing", name)
			}
		})
	}
}

func TestACleanWrapperOverALeakingCauseIsCaught(t *testing.T) {
	t.Parallel()

	err := leakingWrapper{cause: fmt.Errorf("open frame holding %s", knownPlaintext)}
	if err.Error() != "seal: corrupt ciphertext" {
		t.Fatalf("test fixture: the wrapper's own message is %q, which is not clean", err.Error())
	}
	leaks := errorLeaks(err, canaryNeedles())
	if len(leaks) == 0 {
		t.Fatal("a clean wrapper over a cause holding the plaintext was reported as leaking nothing; " +
			"the canary is only checking Error() and not the Unwrap chain")
	}
	for _, leak := range leaks {
		if strings.Contains(leak.rendering, "wrapped cause") {
			return
		}
	}
	t.Errorf("the leak was reported, but not against the wrapped cause: %v", leaks)
}

// TestACeilingRefusalIsNotALeak is the other direction, and it is the one the
// dropped length needle exists for. A *LimitError must name the length it
// refused — a refusal a caller cannot size its retry against is a refusal it
// cannot act on — so an error that says "39 bytes" about a 39-byte plaintext
// has to pass this canary. The test asserts both halves: that the length is in
// the message, and that the canary is nonetheless silent.
func TestACeilingRefusalIsNotALeak(t *testing.T) {
	t.Parallel()

	dek, addr := streamFixture(t)
	_, err := seal.EncryptObject(dek, addr, knownPlaintext, seal.Limits{MaxPlaintext: 8})
	if err == nil {
		t.Fatal("EncryptObject over its ceiling: err = nil")
	}
	if want := fmt.Sprintf("%d bytes", len(knownPlaintext)); !strings.Contains(err.Error(), want) {
		t.Fatalf("test fixture: %q does not contain %q, so this test no longer exercises the length needle",
			err.Error(), want)
	}
	if leaks := errorLeaks(err, canaryNeedles()); len(leaks) != 0 {
		t.Errorf("a ceiling refusal was reported as a leak: %v; the length needle must stay dropped, "+
			"or this canary fails for the correct behaviour of a security control", leaks)
	}
}

// TestSealsOwnSentinelsAreClean is the baseline. Every sentinel seal returns
// across a package boundary is rendered through the detector, so a future
// sentinel whose message quoted its input could not be added quietly.
func TestSealsOwnSentinelsAreClean(t *testing.T) {
	t.Parallel()

	needles := canaryNeedles()
	for _, err := range []error{
		seal.ErrCorrupt, seal.ErrInvalidDEK, seal.ErrInvalidAddress, seal.ErrRange,
		seal.ErrClosed, seal.ErrInvalidFrameSize, seal.ErrLimitExceeded,
		seal.ErrUnknownLength, seal.ErrInvalidLimit,
	} {
		if leaks := errorLeaks(err, needles); len(leaks) != 0 {
			t.Errorf("%v: %v", err, leaks)
		}
	}
}

// TestTheNeedleSetDropsOnlyTheLengthNeedle pins the one deliberate difference
// from redaction.go's set, so that a copy which dropped more — or which
// stopped covering the plaintext at all — fails here.
func TestTheNeedleSetDropsOnlyTheLengthNeedle(t *testing.T) {
	t.Parallel()

	got := errorNeedles(knownMaterial, knownPlaintext)
	want := 0
	for _, source := range [][]byte{knownMaterial, knownPlaintext} {
		for _, n := range leakNeedles(source) {
			if !n.qualified {
				want++
			}
		}
	}
	if len(got) != want {
		t.Fatalf("errorNeedles returned %d needles, want %d (leakNeedles' set for both sentinels, "+
			"less the one qualified length needle each)", len(got), want)
	}
	for _, n := range got {
		if n.qualified {
			t.Errorf("a qualified needle survived: %s", n.what)
		}
		if !strings.HasPrefix(n.what, "key material") && !strings.HasPrefix(n.what, "plaintext") {
			t.Errorf("needle %q does not say which sentinel it belongs to", n.what)
		}
	}
}

// TestUnwrapChainIsWalkedToTheEnd guards the loop in errorRenderings: a chain
// of three errors must produce three cause renderings, not one.
func TestUnwrapChainIsWalkedToTheEnd(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
	causes := 0
	for _, r := range errorRenderings(err) {
		if strings.Contains(r.name, "wrapped cause") {
			causes++
		}
	}
	if causes != 2 {
		t.Errorf("a two-link Unwrap chain produced %d cause renderings, want 2", causes)
	}
}
