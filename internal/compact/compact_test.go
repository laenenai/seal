package compact_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/compact"
	"github.com/laenenai/seal/internal/domain"
)

func testDEK(t *testing.T) keyring.DEK {
	t.Helper()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("keyring.NewDEK(): %v", err)
	}
	t.Cleanup(dek.Destroy)
	return dek
}

func testAddress(t *testing.T, parts ...string) domain.RecordAddress {
	t.Helper()
	addr, err := domain.NewRecordAddress(parts...)
	if err != nil {
		t.Fatalf("NewRecordAddress(%q): %v", parts, err)
	}
	return addr
}

// defaultLimits is what every one-shot entry point applies when a caller
// configures nothing: the 1 MiB plaintext ceiling, and a ciphertext ceiling
// derived from it.
func defaultLimits(t *testing.T) domain.Resolved {
	t.Helper()
	r, err := domain.Limits{}.ResolveCompact()
	if err != nil {
		t.Fatalf("Limits{}.ResolveCompact: %v", err)
	}
	return r
}

func unlimited(t *testing.T) domain.Resolved {
	t.Helper()
	r, err := domain.Limits{MaxPlaintext: domain.Unlimited, MaxCiphertext: domain.Unlimited}.ResolveCompact()
	if err != nil {
		t.Fatalf("unlimited ResolveCompact: %v", err)
	}
	return r
}

func TestSealOpen_RoundTripAcrossSizes(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)

	for _, size := range []int{0, 1, 20, 1024, 65536, int(domain.DefaultMaxPlaintext)} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i * 7)
			}
			record, err := compact.Seal(dek, addr, plaintext, limits)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			got, err := compact.Open(dek, addr, record, limits)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip mismatch at size %d", size)
			}
		})
	}
}

// TestRecordOverheadIsTheDocumentedThirtyThreeBytes pins the size claim the
// format exists for. A record is its plaintext plus one version byte, a
// 16-byte salt and a 16-byte tag — and no nonce, because the nonce is derived.
// A change that started storing the nonce would be a 12-byte regression on
// every one of tens of millions of records, and would fail here.
func TestRecordOverheadIsTheDocumentedThirtyThreeBytes(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)

	for _, size := range []int{0, 1, 20, 4096} {
		record, err := compact.Seal(dek, addr, make([]byte, size), limits)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", size, err)
		}
		if want := size + 33; len(record) != want {
			t.Errorf("a %d-byte value sealed to %d bytes, want %d (33 bytes of overhead)", size, len(record), want)
		}
		if int64(len(record)) != compact.Overhead(int64(size)) {
			t.Errorf("Overhead(%d) = %d disagrees with the %d bytes Seal produced",
				size, compact.Overhead(int64(size)), len(record))
		}
	}
}

// TestOpen_RefusesRelocationToAnotherAddress is the module's central claim,
// and it is leak channel #17 in the kgs design: an encrypted salary moved onto
// another row must become a decryption failure rather than a silent wrong
// answer. Every component is varied independently, because a binding that
// covers two of three is a binding that lets the third be rewritten.
func TestOpen_RefusesRelocationToAnotherAddress(t *testing.T) {
	dek := testDEK(t)
	limits := defaultLimits(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	record, err := compact.Seal(dek, addr, []byte("147500 EUR per year"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	elsewhere := map[string][]string{
		"another graph":             {"graph-2", "fact-1", "salary"},
		"another fact in the graph": {"graph-1", "fact-2", "salary"},
		"another attribute":         {"graph-1", "fact-1", "bonus"},
		"a shorter address":         {"graph-1", "fact-1"},
		"a longer address":          {"graph-1", "fact-1", "salary", "v2"},
		"the same parts reordered":  {"salary", "fact-1", "graph-1"},
	}
	for name, parts := range elsewhere {
		t.Run(name, func(t *testing.T) {
			wrong := testAddress(t, parts...)
			if _, err := compact.Open(dek, wrong, record, limits); !errors.Is(err, domain.ErrCorrupt) {
				t.Fatalf("opening a record at %s: err = %v, want ErrCorrupt", name, err)
			}
		})
	}
}

// TestOpen_RefusesAnAddressThatSplitsTheSameBytesDifferently is why the
// component count is encoded in the AAD and not left implicit.
// Length-prefixed concatenation is injective at a fixed arity — which is all
// the framed format needs — but not across differing arities, so without the
// count a caller could construct two distinct addresses with the same encoded
// form.
func TestOpen_RefusesAnAddressThatSplitsTheSameBytesDifferently(t *testing.T) {
	dek := testDEK(t)
	limits := defaultLimits(t)
	sealed := testAddress(t, "ab", "c")
	record, err := compact.Seal(dek, sealed, []byte("v"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, parts := range [][]string{{"a", "bc"}, {"abc"}, {"a", "b", "c"}} {
		if _, err := compact.Open(dek, testAddress(t, parts...), record, limits); !errors.Is(err, domain.ErrCorrupt) {
			t.Errorf("opening under %q: err = %v, want ErrCorrupt", parts, err)
		}
	}
	// And the address it was actually sealed under still opens, so the test
	// is distinguishing addresses rather than refusing everything.
	if _, err := compact.Open(dek, sealed, record, limits); err != nil {
		t.Fatalf("opening under the genuine address: %v", err)
	}
}

// TestOpen_RefusesAFlippedBitAnywhere is the compact format's whole-record
// analogue of the framed format's bit-flip tests, and it is stronger than
// picking positions: every byte of the record is flipped in turn, version byte
// and salt included, and every one must fail. The version byte and salt carry
// no tag of their own; they are covered because the whole prefix is in the AAD
// and the salt is the key's input.
func TestOpen_RefusesAFlippedBitAnywhere(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(dek, addr, []byte("147500 EUR per year"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for i := range record {
		tampered := append([]byte{}, record...)
		tampered[i] ^= 0x01
		if _, err := compact.Open(dek, addr, tampered, limits); !errors.Is(err, domain.ErrCorrupt) {
			t.Errorf("byte %d of %d flipped: err = %v, want ErrCorrupt", i, len(record), err)
		}
	}
}

// TestOpen_RefusesEveryTruncation drops the record at every length short of
// its own, which subsumes "a lost tag" and "a lost salt" without having to
// know where either sits.
func TestOpen_RefusesEveryTruncation(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(dek, addr, []byte("147500 EUR per year"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for n := 0; n < len(record); n++ {
		if _, err := compact.Open(dek, addr, record[:n], limits); !errors.Is(err, domain.ErrCorrupt) {
			t.Errorf("record truncated to %d of %d bytes: err = %v, want ErrCorrupt", n, len(record), err)
		}
	}
}

func TestOpen_RefusesAnUnknownFormatVersion(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(dek, addr, []byte("value"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Version 1 is the framed stream, which is the mistake a caller actually
	// makes: storing a framed stream in a column a compact reader reads. It
	// must be ErrCorrupt, indistinguishable from a tag failure.
	for _, v := range []byte{0x00, byte(domain.VersionFramed), 0x03, 0xff} {
		tampered := append([]byte{}, record...)
		tampered[0] = v
		if _, err := compact.Open(dek, addr, tampered, limits); !errors.Is(err, domain.ErrCorrupt) {
			t.Errorf("version byte %#x: err = %v, want ErrCorrupt", v, err)
		}
	}
}

func TestOpen_RefusesAnotherDEK(t *testing.T) {
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(testDEK(t), addr, []byte("value"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := compact.Open(testDEK(t), addr, record, limits); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("opening under another DEK: err = %v, want ErrCorrupt", err)
	}
}

func TestSealOpen_RejectAnInvalidDEK(t *testing.T) {
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	good := testDEK(t)
	record, err := compact.Seal(good, addr, []byte("value"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	destroyed, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("keyring.NewDEK(): %v", err)
	}
	destroyed.Destroy()

	for name, dek := range map[string]keyring.DEK{"zero value": {}, "destroyed": destroyed} {
		t.Run(name, func(t *testing.T) {
			if _, err := compact.Seal(dek, addr, []byte("value"), limits); !errors.Is(err, domain.ErrInvalidDEK) {
				t.Errorf("Seal: err = %v, want ErrInvalidDEK", err)
			}
			if _, err := compact.Open(dek, addr, record, limits); !errors.Is(err, domain.ErrInvalidDEK) {
				t.Errorf("Open: err = %v, want ErrInvalidDEK", err)
			}
			if _, err := compact.NewWriter(io.Discard, dek, addr, limits); !errors.Is(err, domain.ErrInvalidDEK) {
				t.Errorf("NewWriter: err = %v, want ErrInvalidDEK", err)
			}
		})
	}
}

// TestSeal_DrawsAFreshSaltPerRecord is the test behind the birthday-bound
// claim: the per-record key is only per-record if the salt actually varies.
// Two seals of identical plaintext at an identical address must differ in
// every byte after the version byte, which also means the format is not
// deterministic and does not leak equality of values.
func TestSeal_DrawsAFreshSaltPerRecord(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)

	seen := make(map[string]bool)
	const n = 64
	for i := 0; i < n; i++ {
		record, err := compact.Seal(dek, addr, []byte("the same value every time"), limits)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		salt := string(record[1:domain.CompactPrefixSize])
		if seen[salt] {
			t.Fatalf("the same salt appeared twice in %d records: the per-record key is not per-record", n)
		}
		seen[salt] = true
	}
}

// TestVectors_MatchCommittedTestdata decrypts the committed ciphertext
// directly. It must never be replaced by re-encrypting plaintext_hex and
// comparing: the whole point is to catch a silent wire-format change, which
// only decrypting a byte-for-byte pinned fixture can detect. If it fails, the
// format has changed and the answer is to change it back.
func TestVectors_MatchCommittedTestdata(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read testdata/vectors.json: %v", err)
	}
	var doc struct {
		Vectors []struct {
			Name          string   `json:"name"`
			DEKHex        string   `json:"dek_hex"`
			Address       []string `json:"address"`
			PlaintextHex  string   `json:"plaintext_hex"`
			CiphertextHex string   `json:"ciphertext_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal vectors.json: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("testdata/vectors.json has no vectors")
	}

	for _, vec := range doc.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			dekBytes, err := hex.DecodeString(vec.DEKHex)
			if err != nil {
				t.Fatalf("decode dek_hex: %v", err)
			}
			dek, err := keyring.DEKFrom(dekBytes)
			if err != nil {
				t.Fatalf("keyring.DEKFrom: %v", err)
			}
			defer dek.Destroy()

			wantPlaintext, err := hex.DecodeString(vec.PlaintextHex)
			if err != nil {
				t.Fatalf("decode plaintext_hex: %v", err)
			}
			record, err := hex.DecodeString(vec.CiphertextHex)
			if err != nil {
				t.Fatalf("decode ciphertext_hex: %v", err)
			}
			addr, err := domain.NewRecordAddress(vec.Address...)
			if err != nil {
				t.Fatalf("NewRecordAddress: %v", err)
			}

			got, err := compact.Open(dek, addr, record, defaultLimits(t))
			if err != nil {
				t.Fatalf("decrypt committed vector %q: %v", vec.Name, err)
			}
			if !bytes.Equal(got, wantPlaintext) {
				t.Fatalf("decrypted vector %q = %x, want %x", vec.Name, got, wantPlaintext)
			}
		})
	}
}

// TestCeilings_EnforceTheFiveRules is CHARTER.md's ceiling discipline, one
// subtest per rule, so a change that drops one fails by name.
func TestCeilings_EnforceTheFiveRules(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")

	t.Run("rule 1: the plaintext ceiling bounds what a caller hands us", func(t *testing.T) {
		limits, err := domain.Limits{MaxPlaintext: 16}.ResolveCompact()
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		record, err := compact.Seal(dek, addr, make([]byte, 17), limits)
		if !errors.Is(err, domain.ErrLimitExceeded) {
			t.Fatalf("Seal of 17 bytes under a 16-byte ceiling: err = %v, want ErrLimitExceeded", err)
		}
		if record != nil {
			t.Error("a refused Seal returned a record; rule 4 says a refusal, never a partial result")
		}
		var limitErr *domain.LimitError
		if !errors.As(err, &limitErr) || limitErr.Limit != "max plaintext" {
			t.Fatalf("err = %v, want a *LimitError naming max plaintext", err)
		}
		if limitErr.Max != 16 || limitErr.Actual != 17 {
			t.Errorf("LimitError = {Max:%d Actual:%d}, want {16 17}", limitErr.Max, limitErr.Actual)
		}
	})

	t.Run("rule 1: the ciphertext ceiling is the one an attacker controls", func(t *testing.T) {
		// Generous on the way in, strict on the way out: exactly the
		// asymmetry rule 1 exists for, and a single limit could not express
		// it.
		writeLimits := unlimited(t)
		record, err := compact.Seal(dek, addr, make([]byte, 4096), writeLimits)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		readLimits, err := domain.Limits{MaxPlaintext: domain.Unlimited, MaxCiphertext: 1024}.ResolveCompact()
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		plain, err := compact.Open(dek, addr, record, readLimits)
		if !errors.Is(err, domain.ErrLimitExceeded) {
			t.Fatalf("Open of a %d-byte record under a 1024-byte ciphertext ceiling: err = %v, want ErrLimitExceeded",
				len(record), err)
		}
		if plain != nil {
			t.Error("a refused Open returned plaintext; rule 4 says a refusal, never a partial result")
		}
		var limitErr *domain.LimitError
		if !errors.As(err, &limitErr) || limitErr.Limit != "max ciphertext" {
			t.Fatalf("err = %v, want a *LimitError naming max ciphertext", err)
		}
	})

	t.Run("rule 2: the streaming writer never buffers past its ceiling", func(t *testing.T) {
		limits, err := domain.Limits{MaxPlaintext: 32}.ResolveCompact()
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		var out bytes.Buffer
		w, err := compact.NewWriter(&out, dek, addr, limits)
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		if _, err := w.Write(make([]byte, 24)); err != nil {
			t.Fatalf("first Write: %v", err)
		}
		if _, err := w.Write(make([]byte, 24)); !errors.Is(err, domain.ErrLimitExceeded) {
			t.Fatalf("the Write that crosses the ceiling: err = %v, want ErrLimitExceeded", err)
		}
		if err := w.Close(); !errors.Is(err, domain.ErrLimitExceeded) {
			t.Errorf("Close after a refused Write: err = %v, want the sticky ErrLimitExceeded", err)
		}
		if out.Len() != 0 {
			t.Errorf("a refused writer still wrote %d bytes; nothing partial may be emitted", out.Len())
		}
	})

	t.Run("rule 3: an undeclarable length fails closed", func(t *testing.T) {
		limits := defaultLimits(t)
		record, err := compact.Seal(dek, addr, []byte("value"), limits)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}

		// A *bytes.Reader has Len, so it declares its length and is accepted.
		if _, err := compact.NewReader(bytes.NewReader(record), dek, addr, limits); err != nil {
			t.Fatalf("NewReader over a *bytes.Reader: %v", err)
		}

		// An opaque reader cannot, so with a ceiling in force it is refused
		// rather than read.
		opaque := io.Reader(struct{ io.Reader }{bytes.NewReader(record)})
		if _, err := compact.NewReader(opaque, dek, addr, limits); !errors.Is(err, domain.ErrUnknownLength) {
			t.Fatalf("NewReader over a reader with no declarable length: err = %v, want ErrUnknownLength", err)
		}

		// With no ceiling there is nothing an unknown length could exceed, so
		// the same reader is accepted. Fail-closed, not fail-always.
		opaque = io.Reader(struct{ io.Reader }{bytes.NewReader(record)})
		r, err := compact.NewReader(opaque, dek, addr, unlimited(t))
		if err != nil {
			t.Fatalf("NewReader over the same reader with no ceiling: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, []byte("value")) {
			t.Fatalf("unbounded read returned %q", got)
		}
	})

	t.Run("rule 3: a declared length over the ceiling is refused before any read", func(t *testing.T) {
		limits, err := domain.Limits{MaxCiphertext: 8}.ResolveCompact()
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		record, err := compact.Seal(dek, addr, []byte("value"), unlimited(t))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		counted := &countingReader{r: bytes.NewReader(record), n: int64(len(record))}
		if _, err := compact.NewReader(counted, dek, addr, limits); !errors.Is(err, domain.ErrLimitExceeded) {
			t.Fatalf("NewReader over an oversized record: err = %v, want ErrLimitExceeded", err)
		}
		if counted.read != 0 {
			t.Errorf("the refusal read %d bytes; rule 2 says the check comes before the read", counted.read)
		}
	})

	t.Run("rule 5: zero is never silently unbounded", func(t *testing.T) {
		// A Limits whose fields are zero means the default, not unbounded —
		// which is the property that makes an unfinished struct literal safe.
		limits := defaultLimits(t)
		if limits.MaxPlaintext != domain.DefaultMaxPlaintext {
			t.Errorf("a zero MaxPlaintext resolved to %d, want the %d-byte default",
				limits.MaxPlaintext, domain.DefaultMaxPlaintext)
		}
		if want := domain.DefaultMaxPlaintext + domain.CompactOverhead; limits.MaxCiphertext != want {
			t.Errorf("a zero MaxCiphertext resolved to %d, want the derived %d", limits.MaxCiphertext, want)
		}
		if _, err := compact.Seal(testDEK(t), addr, make([]byte, domain.DefaultMaxPlaintext+1), limits); !errors.Is(err, domain.ErrLimitExceeded) {
			t.Errorf("a value one byte over the default ceiling: err = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("a nonsensical ceiling is refused rather than guessed at", func(t *testing.T) {
		if _, err := (domain.Limits{MaxPlaintext: -2}).ResolveCompact(); !errors.Is(err, domain.ErrInvalidLimit) {
			t.Errorf("MaxPlaintext=-2: err = %v, want ErrInvalidLimit", err)
		}
		if _, err := (domain.Limits{MaxCiphertext: -7}).ResolveCompact(); !errors.Is(err, domain.ErrInvalidLimit) {
			t.Errorf("MaxCiphertext=-7: err = %v, want ErrInvalidLimit", err)
		}
	})
}

// countingReader declares its length through Len, like a *bytes.Reader, and
// records how much was actually read through it.
type countingReader struct {
	r    io.Reader
	n    int64
	read int64
}

func (c *countingReader) Len() int { return int(c.n - c.read) }

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

type fakeFileInfo struct {
	size int64
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// negativeStatReader reports a regular file with a size smaller than its
// current offset, which makes the derived remaining length negative while it
// still serves bytes.
type negativeStatReader struct {
	data []byte
	off  int64
	size int64
	read int64
}

func (r *negativeStatReader) Read(p []byte) (int, error) {
	if r.off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += int64(n)
	r.read += int64(n)
	return n, nil
}

func (r *negativeStatReader) Stat() (fs.FileInfo, error) { return fakeFileInfo{size: r.size}, nil }

func (r *negativeStatReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.off = offset
	case io.SeekCurrent:
		r.off += offset
	case io.SeekEnd:
		r.off = int64(len(r.data)) + offset
	default:
		return 0, errors.New("bad whence")
	}
	return r.off, nil
}

func TestWriterAndReader_RoundTrip(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	plaintext := []byte("a value arriving as a stream of writes")

	var out bytes.Buffer
	w, err := compact.NewWriter(&out, dek, addr, limits)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for _, chunk := range bytes.SplitAfter(plaintext, []byte(" ")) {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("more")); !errors.Is(err, domain.ErrClosed) {
		t.Errorf("Write after Close: err = %v, want ErrClosed", err)
	}

	r, err := compact.NewReader(bytes.NewReader(out.Bytes()), dek, addr, limits)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip through the streaming shapes mismatched")
	}
}

func TestNewReader_FailsClosedOnANegativeDerivedLength(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(dek, addr, []byte("value"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Stat reports 10 bytes, but the current offset is 100: the derived
	// remaining length is negative. The reader still serves bytes, so the old
	// code would fall through to an unbounded io.ReadAll.
	reader := &negativeStatReader{data: record, off: 100, size: 10}
	if _, err := compact.NewReader(reader, dek, addr, limits); !errors.Is(err, domain.ErrUnknownLength) {
		t.Fatalf("NewReader with a negative derived length: err = %v, want ErrUnknownLength", err)
	}
	if reader.read != 0 {
		t.Fatalf("NewReader read %d bytes from a negative derived length; it must fail closed before reading", reader.read)
	}
}

func TestNewReader_RefusesAnOverReportedLength(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(dek, addr, []byte("value"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	reader := &countingReader{r: bytes.NewReader(record), n: int64(len(record) + 10)}
	if _, err := compact.NewReader(reader, dek, addr, limits); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("NewReader with an over-reported length: err = %v, want ErrCorrupt", err)
	}
}

func TestNewReader_RefusesTrailingData(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	record, err := compact.Seal(dek, addr, []byte("value"), limits)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	data := append(append([]byte{}, record...), []byte("trailing")...)
	reader := &countingReader{r: bytes.NewReader(data), n: int64(len(record))}
	if _, err := compact.NewReader(reader, dek, addr, limits); !errors.Is(err, domain.ErrCorrupt) {
		t.Fatalf("NewReader with trailing data: err = %v, want ErrCorrupt", err)
	}
}

func TestNewReader_ChecksThePlaintextCeilingBeforeAllocation(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits, err := domain.Limits{MaxPlaintext: 1024, MaxCiphertext: domain.Unlimited}.ResolveCompact()
	if err != nil {
		t.Fatalf("ResolveCompact: %v", err)
	}

	const declared = 10 << 20
	reader := &countingReader{r: bytes.NewReader(make([]byte, declared)), n: declared}
	if _, err := compact.NewReader(reader, dek, addr, limits); !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("NewReader with an oversized declared length: err = %v, want ErrLimitExceeded", err)
	}
	if reader.read != 0 {
		t.Fatalf("the refusal read %d bytes; the plaintext ceiling must be checked before allocation and reading", reader.read)
	}
}

// TestNoRenderingOfACompactTypeDisclosesItsMaterial covers the leak channel
// the streaming shapes would otherwise have: the writer holds the whole
// plaintext and the reader holds the whole decrypted plaintext, both in
// unexported fields of a value fmt is handed as an interface. Without
// fmt.Formatter, %+v reflects the buffer.
func TestNoRenderingOfACompactTypeDisclosesItsMaterial(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")
	limits := defaultLimits(t)
	const sentinel = "PLAINTEXT-CANARY-SENTINEL-19a2f"

	var out bytes.Buffer
	w, err := compact.NewWriter(&out, dek, addr, limits)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write([]byte(sentinel)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Rendered before Close, so the buffer is at its fullest.
	assertRedacted(t, "CompactWriter", w, sentinel)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := compact.NewReader(bytes.NewReader(out.Bytes()), dek, addr, limits)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	assertRedacted(t, "CompactReader", r, sentinel)
}

func assertRedacted(t *testing.T, name string, subject any, sentinel string) {
	t.Helper()
	// A variable rather than literal format strings: go vet's printf analyzer
	// only inspects constant formats, and a literal fmt.Sprintf("%d", w) here
	// would be a vet failure for code whose purpose is to provoke that case.
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%U", "%b", "%o"}

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
		"the plaintext":     sentinel,
		"its lowercase hex": hex.EncodeToString([]byte(sentinel)),
		"byte-wise decimal, as %d prints it": func() string {
			parts := make([]string, len(sentinel))
			for i := range sentinel {
				parts[i] = fmt.Sprintf("%d", sentinel[i])
			}
			return strings.Join(parts, " ")
		}(),
	}
	for _, got := range rendered {
		for what, needle := range needles {
			if strings.Contains(got, needle) {
				t.Errorf("%s: a rendering disclosed %s: %q", name, what, got)
			}
		}
		if !strings.Contains(strings.ToLower(got), "redact") {
			t.Errorf("%s: rendering %q carries no redaction marker", name, got)
		}
	}
}

// TestOpen_EnforcesThePlaintextCeilingToo covers the asymmetry a caller can
// create and would not expect to be a hole: MaxCiphertext set to Unlimited
// explicitly, with MaxPlaintext left in place.
//
// The derived default makes the two ceilings agree, so this only arises when
// someone opts one of them out by hand — and reading that as "no bound on
// either" would be the surprising answer rather than the safe one.
func TestOpen_EnforcesThePlaintextCeilingToo(t *testing.T) {
	dek := testDEK(t)
	addr := testAddress(t, "graph-1", "fact-1", "salary")

	record, err := compact.Seal(dek, addr, make([]byte, 4096), unlimited(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	limits, err := domain.Limits{MaxPlaintext: 1024, MaxCiphertext: domain.Unlimited}.ResolveCompact()
	if err != nil {
		t.Fatalf("ResolveCompact: %v", err)
	}
	plain, err := compact.Open(dek, addr, record, limits)
	if !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("Open of a 4096-byte value under a 1024-byte plaintext ceiling: err = %v, want ErrLimitExceeded", err)
	}
	if plain != nil {
		t.Error("a refused Open returned plaintext")
	}
	var limitErr *domain.LimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != "max plaintext" {
		t.Fatalf("err = %v, want a *LimitError naming max plaintext", err)
	}
	if limitErr.Actual != 4096 {
		t.Errorf("LimitError.Actual = %d, want the 4096 bytes the record declares", limitErr.Actual)
	}
}
