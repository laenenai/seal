package seal_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal"
	"github.com/laenenai/seal/sealtest"
)

// TestTheDEKWeDependOnStillRedacts holds keyring.DEK — the one material-bearing
// type that crosses this module's boundary — to the shared
// NoSecretLeaksInAnyRendering subtest, which is a byte-for-byte copy of the one
// every other module in this set carries.
//
// Running keyring's own type through this module's copy of the helper looks
// redundant and is not. The assertion is about the version of keyring this
// module depends on, not about keyring's source: a minor release that added an
// exported field, or a change that replaced the DEK's Format method with
// something that honours width by re-rendering the underlying value, would
// leak key material through seal's errors and logs and would pass keyring's own
// CI unchanged if keyring's tests were the ones that had moved. This is the
// assertion at the boundary where the material actually arrives.
//
// seal declares no material-bearing type of its own. Everything it hands back
// — the two framed readers, the encrypt writer, the compact writer and reader —
// holds a derived key schedule or a plaintext buffer, and those are held to
// RendersOnlyARedactionMarker below and inside the conformance suite, because
// their whole value is material and the negative assertion alone would accept
// the wrong reason for passing: a struct whose fields are unexported marshals
// to "{}", which discloses nothing and is indistinguishable from a type that
// holds nothing at all.
func TestTheDEKWeDependOnStillRedacts(t *testing.T) {
	t.Parallel()

	material := []byte("seal-boundary-dek-material-0c7f3")
	if len(material) != 32 {
		t.Fatalf("fixture is %d bytes, a DEK is 32", len(material))
	}
	dek, err := keyring.DEKFrom(material)
	if err != nil {
		t.Fatalf("keyring.DEKFrom: %v", err)
	}
	defer dek.Destroy()

	// The helper applies every rendering to a struct that merely contains the
	// subject as well as to the subject itself, so a containing type needs no
	// subtest of its own here.
	sealtest.NoSecretLeaksInAnyRendering(t, dek, material)
	sealtest.RendersOnlyARedactionMarker(t, dek)
}

// TestEveryValueSealHandsBackRendersOnlyAMarker is the positive half, at the
// facade, over the five values a consumer can hold.
//
// It duplicates a subtest the conformance suite already runs, and that is
// deliberate: the suite's copy holds any implementation of the port to the
// rule, while this one holds *this* module's five concrete types to it even if
// someone later narrows the port. A module whose whole subject is bytes it must
// not disclose is the wrong place to economise on the test that proves it does
// not disclose them.
func TestEveryValueSealHandsBackRendersOnlyAMarker(t *testing.T) {
	t.Parallel()

	dek := testDEK(t)
	objAddr, err := seal.NewObjectAddress("tenant-1", "object-1")
	if err != nil {
		t.Fatalf("NewObjectAddress: %v", err)
	}
	recAddr, err := seal.NewRecordAddress("graph-1", "fact-1", "salary")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}

	stream, err := seal.EncryptObject(dek, objAddr, make([]byte, 200), seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptObject: %v", err)
	}
	record, err := seal.EncryptRecord(dek, recAddr, make([]byte, 200), seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}

	subjects := map[string]func(t *testing.T) any{
		"EncryptWriter": func(t *testing.T) any {
			t.Helper()
			w, err := seal.NewEncryptWriter(io.Discard, dek, objAddr)
			if err != nil {
				t.Fatalf("NewEncryptWriter: %v", err)
			}
			return w
		},
		"DecryptReader": func(t *testing.T) any {
			t.Helper()
			r, err := seal.NewDecryptReader(bytes.NewReader(stream), dek, objAddr, seal.Unlimited)
			if err != nil {
				t.Fatalf("NewDecryptReader: %v", err)
			}
			return r
		},
		"DecryptRangeReader": func(t *testing.T) any {
			t.Helper()
			r, err := seal.NewDecryptRangeReader(
				bytes.NewReader(stream), int64(len(stream)), dek, objAddr, 0, 10)
			if err != nil {
				t.Fatalf("NewDecryptRangeReader: %v", err)
			}
			return r
		},
		"RecordWriter": func(t *testing.T) any {
			t.Helper()
			w, err := seal.NewRecordWriter(io.Discard, dek, recAddr, seal.Limits{})
			if err != nil {
				t.Fatalf("NewRecordWriter: %v", err)
			}
			if _, err := w.Write(make([]byte, 200)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			return w
		},
		"RecordReader": func(t *testing.T) any {
			t.Helper()
			r, err := seal.NewRecordReader(bytes.NewReader(record), dek, recAddr, seal.Limits{})
			if err != nil {
				t.Fatalf("NewRecordReader: %v", err)
			}
			return r
		},
	}

	for name, build := range subjects {
		t.Run(name, func(t *testing.T) {
			sealtest.RendersOnlyARedactionMarker(t, build(t))
		})
	}
}
