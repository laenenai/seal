package seal_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/laenenai/seal"
	"github.com/laenenai/seal/sealtest"
)

// TestFramedSealerConformance runs the StreamSealer contract against this
// module's own framed implementation. A consumer with its own implementation —
// CAS, which has one today — runs the same function against that, which is
// what makes "has adopted seal" something CI can answer.
//
// The factory is called once per subtest with that subtest's own *T, which is
// the convention's shape; this implementation needs no per-subtest state, and
// an implementation that does registers its teardown with t.Cleanup inside the
// factory.
func TestFramedSealerConformance(t *testing.T) {
	t.Parallel()
	sealtest.RunStreamSealerSuite(t, func(*testing.T) seal.StreamSealer { return seal.Framed() })
}

func TestCompactSealerConformance(t *testing.T) {
	t.Parallel()
	sealtest.RunRecordSealerSuite(t, func(*testing.T) seal.RecordSealer { return seal.Compact() })
}

// TestTheTwoFormatsAreNotInterchangeable is the version space made testable.
// Both formats take a DEK and produce bytes, and both are reachable from one
// package, so the mistake a caller actually makes is storing one and reading
// the other — a framed stream in a column a record reader reads, or the
// reverse after a schema change.
//
// Each version is bound into its own additional authenticated data, so the
// answer is ErrCorrupt rather than a plausible-looking wrong plaintext. This
// is what a shared magic prefix across the two shapes would have bought, and
// the reason docs/format.md does not spend bytes on one.
func TestTheTwoFormatsAreNotInterchangeable(t *testing.T) {
	t.Parallel()

	dek := testDEK(t)
	objAddr, err := seal.NewObjectAddress("tenant-1", "object-1")
	if err != nil {
		t.Fatalf("NewObjectAddress: %v", err)
	}
	recAddr, err := seal.NewRecordAddress("tenant-1", "object-1")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	plaintext := []byte("a value either format would carry happily")

	stream, err := seal.EncryptObject(dek, objAddr, plaintext, seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptObject: %v", err)
	}
	record, err := seal.EncryptRecord(dek, recAddr, plaintext, seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}

	if _, err := seal.DecryptRecord(dek, recAddr, stream, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
		t.Errorf("opening a framed stream as a compact record: err = %v, want ErrCorrupt", err)
	}
	if _, err := seal.DecryptObject(dek, objAddr, record, seal.Limits{}); !errors.Is(err, seal.ErrCorrupt) {
		t.Errorf("opening a compact record as a framed stream: err = %v, want ErrCorrupt", err)
	}
}

// TestTheCompactRecordIsSmallerThanOneFramedFrame pins the size claim the
// compact format exists for, in the only units that matter: what each shape
// costs on a short value.
//
// The numbers are stated rather than asserted loosely, because the honest
// figure is modest and a vague assertion would let it quietly get worse. 33
// bytes against 41 on a 20-byte literal is 165% overhead against 205%.
func TestTheCompactRecordIsSmallerThanOneFramedFrame(t *testing.T) {
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
	plaintext := make([]byte, 20)

	stream, err := seal.EncryptObject(dek, objAddr, plaintext, seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptObject: %v", err)
	}
	record, err := seal.EncryptRecord(dek, recAddr, plaintext, seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}

	if got, want := len(stream)-len(plaintext), 41; got != want {
		t.Errorf("a single-frame stream costs %d bytes over its plaintext, want %d", got, want)
	}
	if got, want := len(record)-len(plaintext), seal.CompactOverhead; got != want {
		t.Errorf("a compact record costs %d bytes over its plaintext, want %d", got, want)
	}
	if seal.CompactOverhead != 33 {
		t.Errorf("CompactOverhead = %d, want 33: the documented figure changed", seal.CompactOverhead)
	}
}

// TestNewRecordReader_AcceptsAFileAsADeclaredLength covers the length-probe
// path a real caller hits that *bytes.Reader does not: an *os.File has no Len
// method, and the ceiling discipline has to establish its length from Stat and
// Seek rather than refuse it.
func TestNewRecordReader_AcceptsAFileAsADeclaredLength(t *testing.T) {
	t.Parallel()

	dek := testDEK(t)
	addr, err := seal.NewRecordAddress("graph-1", "fact-1", "salary")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	record, err := seal.EncryptRecord(dek, addr, []byte("value on disk"), seal.Limits{})
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}

	path := filepath.Join(t.TempDir(), "record.bin")
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path) //nolint:gosec // a path this test just wrote inside t.TempDir()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close() //nolint:errcheck // read-only handle in a test

	r, err := seal.NewRecordReader(f, dek, addr, seal.Limits{})
	if err != nil {
		t.Fatalf("NewRecordReader over an *os.File: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, []byte("value on disk")) {
		t.Fatalf("read %q from disk", got)
	}
}

// testDEK is sealtest.NewDEK, and it is a one-line forward on purpose: that
// fixture exists because seal's public API has no DEK constructor and will not
// get one, so a consumer writing a test of its own against seal needs
// somewhere to get a key that is not keyring's main require block. Using it
// here, from a package that is not sealtest, is what keeps the claim honest —
// a fixture only the suite itself calls is not a fixture a consumer can rely
// on.
func testDEK(t *testing.T) seal.DEK {
	t.Helper()
	return sealtest.NewDEK(t)
}
