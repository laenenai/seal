package sealtest

// This file is the canary for a failure path's *error*, which is a different
// channel from a value's *rendering* and fails in a different way.
//
// redaction.go holds the rendering half: NoSecretLeaksInAnyRendering and
// RendersOnlyARedactionMarker hold a DEK, a writer and the two readers to what
// they print. Nothing there asserts anything about an error, and an error is
// the one string a caller is most likely to log verbatim, put in an HTTP
// response body, or attach to a trace span. cas/internal/crypto had exactly
// this canary — TestCanary_NoSecretsLeakInErrors — and when CAS adopted seal
// v0.1.0 and deleted its own implementation, its CI stopped running one,
// because the only counterpart lives in seal/internal/framed and no module
// outside seal can import an internal package.
//
// It is a separate file rather than an addition to redaction.go because
// redaction.go is a byte-identical copy shared across keyringtest,
// tenancytest, iamtest and sealtest. Editing it would diverge four copies to
// add something only seal needs; adding beside it costs nothing.
//
// # The needle set is redaction.go's, deliberately not a second one
//
// leakNeedles already enumerates every form material takes in a rendering
// Go actually produces — raw, hex in both cases, base64 in all four alphabets,
// Go and JSON string escaping, and the byte-wise decimal, octal, binary, rune
// and Go-syntax forms. An error is a string like any other, so the same set
// applies, and a second set written here would be a second thing to keep in
// step with a convention that already has one.
//
// What is dropped is the length needle, and only the length needle. It is the
// one needle leakNeedles marks `qualified`, and the qualification is there for
// a reason worth repeating rather than rediscovering: a bare decimal is not a
// disclosure on its own, so the needle fires only as its own token and only
// with "len", "length", "size", "byte" or "bytes" within fourteen characters.
// It was not always so. A Credential rendering its expiry as
// 2026-10-23T15:20:08Z contains a standalone 20 between two colons, so a
// 20-byte secret failed that subtest at 15:20 and passed at 15:21, and a
// security test that fails by the clock gets deleted by whoever is on call.
//
// Here even the qualified form cannot hold, in both directions:
//
//   - A seal DEK's length is 32 bytes for every DEK there will ever be —
//     keyring fixes it and docs/format.md publishes it — so a "32" near the
//     word "bytes" in an error discloses nothing an attacker did not read in
//     the format document.
//   - A plaintext's length is what a ceiling refusal is *required* to report.
//     *LimitError renders as "seal: max plaintext exceeded: 40 bytes, limit
//     8", because a refusal a caller cannot size its retry against is a
//     refusal it cannot act on. Keeping the needle would fail this canary for
//     the correct behaviour of a security control.
//
// So the needle whose only possible firings are a published constant and a
// required disclosure is dropped, and said to be dropped, rather than left in
// to be deleted later by someone who assumes it was a mistake.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal"
)

// knownPlaintext is the plaintext the error canary seals and then provokes
// failures over. Like knownMaterial it is fixed and obviously synthetic, so a
// failure message names something a reader recognises as the test's own bytes,
// and it is well past minMaterialLen so the containment checks are assertions
// rather than coin tosses. Its length is deliberately not 32, so that a
// rendering disclosing its length could not be mistaken for one disclosing the
// DEK's.
var knownPlaintext = []byte("sealtest-plaintext-canary-3b91f7ad-ef02")

// NoSecretLeaksInAnyError asserts that none of the errors in failures
// discloses material or plaintext, in any encoding a rendering produces.
//
// failures maps a path's name — as a reader would name it in a bug report, "a
// wrong DEK", "a truncated stream" — to the error that path returned. Each
// becomes a subtest of that name, and a nil error fails it: an entry whose
// error is nil means the test did not actually provoke the failure it claims
// to be checking, which is the way a canary like this rots. Checking that is
// not pedantry; it is the difference between "no error leaked" and "no error
// happened".
//
// Each error is rendered six ways — Error(), %v, %+v, %s, %q, and every error
// in its Unwrap chain — because an error type may print more under %+v than
// its Error method returns, and because a clean wrapper around a leaking cause
// is still a leak the moment anyone logs the cause.
//
// It is exported, like the two rendering subtests beside it, so that a
// consumer can hold its *own* failure paths to the same assertion. A consumer
// that wraps a seal error with its own context — an object key, a tenant, a
// request id — is building a new error string from one that was clean, and
// that is the place this goes wrong next.
//
// What it does not assert is that an error omits *which check* failed, which
// CONVENTIONS.md requires separately and which seal satisfies by returning one
// indistinguishable ErrCorrupt for every authentication failure. That is a
// property of the sentinel rather than of the material, and it is pinned where
// the sentinel is declared.
func NoSecretLeaksInAnyError(t *testing.T, material, plaintext []byte, failures map[string]error) {
	t.Helper()

	t.Run("NoSecretLeaksInAnyError", func(t *testing.T) {
		if len(material) < minMaterialLen {
			t.Fatalf("material is %d bytes, want at least %d: a shorter sentinel makes this subtest a coin toss",
				len(material), minMaterialLen)
		}
		if len(plaintext) < minMaterialLen {
			t.Fatalf("plaintext is %d bytes, want at least %d: a shorter sentinel makes this subtest a coin toss",
				len(plaintext), minMaterialLen)
		}
		if len(failures) == 0 {
			t.Fatal("no failure paths were provoked, so this subtest asserts nothing")
		}

		needles := errorNeedles(material, plaintext)
		for path, err := range failures {
			t.Run(path, func(t *testing.T) {
				if err == nil {
					t.Fatalf("%s: err = nil, so this path did not actually fail and nothing was asserted "+
						"about its error", path)
				}
				for _, leak := range errorLeaks(err, needles) {
					t.Errorf("%s: %s disclosed the %s: %s", path, leak.rendering, leak.encoding, leak.out)
				}
			})
		}
	})
}

// errorLeaks reports every rendering of err that discloses one of needles. It
// is a function rather than a loop inside the subtest so that errleaks_test.go
// can assert against the detector itself, the way redaction_test.go asserts
// against renderingLeaks: a canary that stopped being able to fail would
// otherwise keep passing.
func errorLeaks(err error, needles []needle) []renderingLeak {
	var leaks []renderingLeak
	for _, r := range errorRenderings(err) {
		for _, n := range needles {
			if n.contained(r.out) {
				leaks = append(leaks, renderingLeak{rendering: r.name, encoding: n.what, out: r.out})
			}
		}
	}
	return leaks
}

// errorNeedles is leakNeedles applied to the key material and to the
// plaintext, with the length needle dropped from both. See this file's header
// comment for why that one needle cannot hold against an error.
func errorNeedles(material, plaintext []byte) []needle {
	var needles []needle
	for _, source := range []struct {
		what string
		b    []byte
	}{{"key material", material}, {"plaintext", plaintext}} {
		for _, n := range leakNeedles(source.b) {
			if n.qualified {
				continue
			}
			n.what = source.what + " (as " + n.what + ")"
			needles = append(needles, n)
		}
	}
	return needles
}

// errorRenderings renders err every way a caller might put it into a log line
// or a response body, including each error in its Unwrap chain.
//
// The verbs are applied through a variable rather than literal format strings
// for the same reason redaction.go's leakVerbs is a variable: go vet's printf
// analyzer only inspects constant formats, and a literal Sprintf of an error
// under %q here would be flagged in CI for code whose purpose is to render an
// error every way there is.
func errorRenderings(err error) []rendering {
	verbs := []string{"%v", "%+v", "%s", "%q"}

	out := make([]rendering, 0, len(verbs)+4)
	out = append(out, rendering{name: "Error()", out: err.Error(), direct: true})
	for _, verb := range verbs {
		out = append(out, rendering{name: "fmt " + verb, out: fmt.Sprintf(verb, err), direct: true})
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
		out = append(out, rendering{
			name: fmt.Sprintf("the wrapped cause %T's Error()", cause),
			out:  cause.Error(),
		})
	}
	return out
}

// runStreamErrorCanary provokes every failure path a StreamSealer has and
// holds each one's error to NoSecretLeaksInAnyError. It is called from
// RunStreamSealerSuite.
//
// The paths are the real ones, driven through the port rather than simulated:
// a wrong DEK, a wrong address, a truncated stream, a tampered header, a
// tampered tag, a DEK holding no material, each of the four ceiling refusals,
// a bad range, a ranged read over a tampered stream, and a Close after a
// partial read of a corrupt tail. The last two matter most and are the two a
// simulated error cannot reach: both types are holding decrypted plaintext in
// a buffer at the moment they fail.
func runStreamErrorCanary(t *testing.T, newSealer func(t *testing.T) seal.StreamSealer) {
	t.Helper()

	t.Run("LeaksNoSecretsInAnyError", func(t *testing.T) {
		s := newSealer(t)
		_, addr := streamFixture(t)

		dek, err := keyring.DEKFrom(knownMaterial)
		if err != nil {
			t.Fatalf("keyring.DEKFrom(knownMaterial): %v", err)
		}
		defer dek.Destroy()

		other, err := keyring.NewDEK()
		if err != nil {
			t.Fatalf("keyring.NewDEK: %v", err)
		}
		defer other.Destroy()

		wrong, err := seal.NewObjectAddress("tenant-2", "sha256:"+hexRepeat("cd", 32))
		if err != nil {
			t.Fatalf("NewObjectAddress: %v", err)
		}

		ciphertext := mustEncryptObject(t, s, dek, addr, knownPlaintext)
		unlimited := seal.Limits{MaxPlaintext: seal.Unlimited}

		tamperedHeader := append([]byte{}, ciphertext...)
		tamperedHeader[0] ^= 0x01
		tamperedTag := append([]byte{}, ciphertext...)
		tamperedTag[len(tamperedTag)-1] ^= 0x01

		failures := map[string]error{}

		_, failures["a wrong DEK"] = s.DecryptObject(other, addr, ciphertext, unlimited)
		_, failures["a wrong address"] = s.DecryptObject(dek, wrong, ciphertext, unlimited)
		_, failures["a truncated stream"] = s.DecryptObject(dek, addr, ciphertext[:len(ciphertext)-1], unlimited)
		_, failures["a tampered header"] = s.DecryptObject(dek, addr, tamperedHeader, unlimited)
		_, failures["a tampered tag"] = s.DecryptObject(dek, addr, tamperedTag, unlimited)
		_, failures["a DEK that holds no material"] = s.EncryptObject(seal.DEK{}, addr, knownPlaintext, unlimited)
		_, failures["a plaintext over the ceiling"] = s.EncryptObject(dek, addr, knownPlaintext,
			seal.Limits{MaxPlaintext: 8})
		_, failures["a ciphertext over the ceiling"] = s.DecryptObject(dek, addr, ciphertext,
			seal.Limits{MaxPlaintext: seal.Unlimited, MaxCiphertext: 8})
		_, failures["a plaintext ceiling exceeded on decrypt"] = s.DecryptObject(dek, addr, ciphertext,
			seal.Limits{MaxPlaintext: 8, MaxCiphertext: seal.Unlimited})
		_, failures["a nonsensical ceiling"] = s.EncryptObject(dek, addr, knownPlaintext,
			seal.Limits{MaxPlaintext: -2})
		_, failures["a zero stream ceiling"] = s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, 0)
		_, failures["a range past the end"] = s.NewDecryptRangeReader(
			bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, int64(len(knownPlaintext))+1, 10)

		// A ranged read over a tampered stream fails while the range reader
		// holds a frame's decrypted plaintext.
		rr, err := s.NewDecryptRangeReader(
			bytes.NewReader(tamperedTag), int64(len(tamperedTag)), dek, addr, 0, int64(len(knownPlaintext)))
		if err != nil {
			failures["a ranged read over a tampered stream"] = err
		} else {
			_, failures["a ranged read over a tampered stream"] = io.ReadAll(rr)
		}

		failures["Close after a partial read of a corrupt tail"] = closeAfterPartialRead(t, s, dek, addr)

		NoSecretLeaksInAnyError(t, knownMaterial, knownPlaintext, failures)
	})
}

// closeAfterPartialRead returns the error from closing a reader that read the
// first bytes of a tail-corrupt multi-frame stream. The stream's first frame
// begins with knownPlaintext, so the reader is holding the sentinel plaintext
// in its buffer at the moment Close reports the corruption — which is the
// state a canary over a simulated error never reaches.
//
// It costs one encrypt and one full decrypt of a stream just over
// 2*seal.FrameSize, because Close authenticates every frame the caller did not
// read. That is a few milliseconds, and it is the price of exercising the one
// path where an implementation holds plaintext and an error at the same time.
func closeAfterPartialRead(
	t *testing.T, s seal.StreamSealer, dek seal.DEK, addr seal.ObjectAddress,
) error {
	t.Helper()

	plaintext := append(append([]byte{}, knownPlaintext...), patterned(2*seal.FrameSize)...)
	ciphertext := mustEncryptObject(t, s, dek, addr, plaintext)
	ciphertext[len(ciphertext)-1] ^= 0x01

	r, err := s.NewDecryptReader(bytes.NewReader(ciphertext), dek, addr, seal.Unlimited)
	if err != nil {
		return err
	}
	if _, err := r.Read(make([]byte, 10)); err != nil {
		// A corruption at the very end should not surface here, but if an
		// implementation reports it early its error is still the one to check.
		_ = r.Close()
		return err
	}
	return r.Close()
}

// runRecordErrorCanary is runStreamErrorCanary for a RecordSealer. It is
// called from RunRecordSealerSuite.
//
// The writer path is here for the same reason the stream's Close path is: a
// compact record has no framing, so NewRecordWriter holds the entire plaintext
// until Close, and a Write refused for crossing the ceiling is refused while
// the writer holds the sentinel.
func runRecordErrorCanary(t *testing.T, newSealer func(t *testing.T) seal.RecordSealer) {
	t.Helper()

	t.Run("LeaksNoSecretsInAnyError", func(t *testing.T) {
		s := newSealer(t)
		_, addr := recordFixture(t)

		dek, err := keyring.DEKFrom(knownMaterial)
		if err != nil {
			t.Fatalf("keyring.DEKFrom(knownMaterial): %v", err)
		}
		defer dek.Destroy()

		other, err := keyring.NewDEK()
		if err != nil {
			t.Fatalf("keyring.NewDEK: %v", err)
		}
		defer other.Destroy()

		wrong, err := seal.NewRecordAddress("graph-2", "fact-2", "bonus")
		if err != nil {
			t.Fatalf("NewRecordAddress: %v", err)
		}

		record := mustEncryptRecord(t, s, dek, addr, knownPlaintext)

		tamperedVersion := append([]byte{}, record...)
		tamperedVersion[0] ^= 0x01
		tamperedTag := append([]byte{}, record...)
		tamperedTag[len(tamperedTag)-1] ^= 0x01

		failures := map[string]error{}

		_, failures["a wrong DEK"] = s.DecryptRecord(other, addr, record, seal.Limits{})
		_, failures["a relocated record"] = s.DecryptRecord(dek, wrong, record, seal.Limits{})
		_, failures["a truncated record"] = s.DecryptRecord(dek, addr, record[:len(record)-1], seal.Limits{})
		_, failures["a tampered version byte"] = s.DecryptRecord(dek, addr, tamperedVersion, seal.Limits{})
		_, failures["a tampered tag"] = s.DecryptRecord(dek, addr, tamperedTag, seal.Limits{})
		_, failures["a DEK that holds no material"] = s.EncryptRecord(seal.DEK{}, addr, knownPlaintext, seal.Limits{})
		_, failures["a plaintext over the ceiling"] = s.EncryptRecord(dek, addr, knownPlaintext,
			seal.Limits{MaxPlaintext: 8})
		_, failures["a ciphertext over the ceiling"] = s.DecryptRecord(dek, addr, record,
			seal.Limits{MaxPlaintext: seal.Unlimited, MaxCiphertext: 8})
		_, failures["a plaintext ceiling exceeded on decrypt"] = s.DecryptRecord(dek, addr, record,
			seal.Limits{MaxPlaintext: 8, MaxCiphertext: seal.Unlimited})
		_, failures["a nonsensical ceiling"] = s.EncryptRecord(dek, addr, knownPlaintext,
			seal.Limits{MaxCiphertext: -7})
		_, failures["an unestablishable input length"] = s.NewRecordReader(
			opaqueReader(record), dek, addr, seal.Limits{})

		// A read of a tampered record, which NewRecordReader authenticates
		// eagerly, so the error arrives from the constructor rather than a
		// Read — with the record's plaintext already in hand.
		_, failures["a read of a tampered record"] = s.NewRecordReader(
			bytes.NewReader(tamperedTag), dek, addr, seal.Limits{})

		// A writer refused mid-value, holding the whole sentinel plaintext.
		w, err := s.NewRecordWriter(io.Discard, dek, addr, seal.Limits{MaxPlaintext: 8})
		if err != nil {
			failures["a write over the writer's ceiling"] = err
		} else {
			_, failures["a write over the writer's ceiling"] = w.Write(knownPlaintext)
		}

		// A write after Close, which an implementation could plausibly answer
		// by quoting the bytes it refused.
		closed, err := s.NewRecordWriter(io.Discard, dek, addr, seal.Limits{})
		if err != nil {
			t.Fatalf("NewRecordWriter: %v", err)
		}
		if _, err := closed.Write(knownPlaintext); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := closed.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		_, failures["a write after Close"] = closed.Write(knownPlaintext)

		NoSecretLeaksInAnyError(t, knownMaterial, knownPlaintext, failures)
	})
}
