package domain_test

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laenenai/seal/internal/domain"
)

func TestNewObjectAddress_RejectsWhatIsUnsafeToBind(t *testing.T) {
	t.Parallel()

	good := "sha256:" + strings.Repeat("ab", 32)
	bad := map[string]string{
		"empty":                 "",
		"a path separator":      "tenants/one",
		"a backslash":           `tenants\one`,
		"a null byte":           "tenant\x00one",
		"a newline":             "tenant\none",
		"a tab":                 "tenant\tone",
		"leading whitespace":    " tenant",
		"trailing whitespace":   "tenant ",
		"an inner space":        "tenant one",
		"a relative path":       "..",
		"a dot":                 ".",
		"invalid UTF-8":         "tenant\xff",
		"longer than the bound": strings.Repeat("t", 257),
	}
	for name, value := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := domain.NewObjectAddress(value, good); !errors.Is(err, domain.ErrInvalidAddress) {
				t.Errorf("tenant %q: err = %v, want ErrInvalidAddress", value, err)
			}
			if _, err := domain.NewObjectAddress("tenant-1", value); !errors.Is(err, domain.ErrInvalidAddress) {
				t.Errorf("object %q: err = %v, want ErrInvalidAddress", value, err)
			}
		})
	}

	// A colon is explicitly allowed: a content address's canonical form is
	// "<algo>:<hex>", and that string is what CAS bound into every frame's
	// AAD, so rejecting it would make this module unable to read CAS's
	// ciphertext.
	addr, err := domain.NewObjectAddress("tenant-1", good)
	if err != nil {
		t.Fatalf("NewObjectAddress with a canonical content address: %v", err)
	}
	if addr.Tenant() != "tenant-1" || addr.Object() != good {
		t.Errorf("address round-tripped as %q/%q", addr.Tenant(), addr.Object())
	}
	if addr.IsZero() {
		t.Error("a constructed address reports IsZero")
	}
	if (domain.ObjectAddress{}).IsZero() != true {
		t.Error("the zero ObjectAddress does not report IsZero")
	}
}

func TestNewRecordAddress_RejectsWhatIsUnsafeToBind(t *testing.T) {
	t.Parallel()

	if _, err := domain.NewRecordAddress(); !errors.Is(err, domain.ErrInvalidAddress) {
		t.Errorf("no components: err = %v, want ErrInvalidAddress", err)
	}
	if _, err := domain.NewRecordAddress("graph", ""); !errors.Is(err, domain.ErrInvalidAddress) {
		t.Errorf("an empty component: err = %v, want ErrInvalidAddress", err)
	}
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = "c"
	}
	if _, err := domain.NewRecordAddress(tooMany...); !errors.Is(err, domain.ErrInvalidAddress) {
		t.Errorf("17 components: err = %v, want ErrInvalidAddress", err)
	}

	addr, err := domain.NewRecordAddress("graph-1", "fact-1", "salary")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	if got := addr.String(); got != "graph-1/fact-1/salary" {
		t.Errorf("String() = %q", got)
	}
}

// TestRecordAddress_PartsIsACopy covers the reason the constructor clones: an
// address is bound into a tag, so a caller that mutated the slice afterwards
// would hold an address that no longer describes the ciphertext.
func TestRecordAddress_PartsIsACopy(t *testing.T) {
	t.Parallel()

	parts := []string{"graph-1", "fact-1", "salary"}
	addr, err := domain.NewRecordAddress(parts...)
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	parts[2] = "bonus"
	if got := addr.Parts()[2]; got != "salary" {
		t.Errorf("mutating the caller's slice changed the address to %q", got)
	}

	returned := addr.Parts()
	returned[0] = "graph-2"
	if got := addr.Parts()[0]; got != "graph-1" {
		t.Errorf("mutating the returned slice changed the address to %q", got)
	}
}

// TestObjectAddress_AADEncodingIsTheCommittedOne pins the AAD bytes the
// committed CAS vectors were sealed under: each component length-prefixed with
// a big-endian uint32, tenant first, and no component count. The count's
// absence is load-bearing, not an omission — adding one would change every
// committed tag.
func TestObjectAddress_AADEncodingIsTheCommittedOne(t *testing.T) {
	t.Parallel()

	addr, err := domain.NewObjectAddress("ten", "obj")
	if err != nil {
		t.Fatalf("NewObjectAddress: %v", err)
	}
	want := []byte{0, 0, 0, 3, 't', 'e', 'n', 0, 0, 0, 3, 'o', 'b', 'j'}
	if got := addr.AppendAAD(nil); !bytes.Equal(got, want) {
		t.Errorf("AppendAAD = %v, want %v", got, want)
	}
}

// TestRecordAddress_AADEncodingCarriesTheComponentCount is the other half of
// that argument. A record address has a variable number of components, so
// length-prefixed concatenation alone is not injective across arities, and the
// count is what makes it so.
func TestRecordAddress_AADEncodingCarriesTheComponentCount(t *testing.T) {
	t.Parallel()

	two, err := domain.NewRecordAddress("ab", "c")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	one, err := domain.NewRecordAddress("abc")
	if err != nil {
		t.Fatalf("NewRecordAddress: %v", err)
	}
	if bytes.Equal(two.AppendAAD(nil), one.AppendAAD(nil)) {
		t.Fatal(`("ab","c") and ("abc") encode to the same AAD: the encoding is not injective`)
	}
	want := []byte{0, 0, 0, 2, 0, 0, 0, 2, 'a', 'b', 0, 0, 0, 1, 'c'}
	if got := two.AppendAAD(nil); !bytes.Equal(got, want) {
		t.Errorf("AppendAAD = %v, want %v", got, want)
	}
}

func TestLimits_ResolveFillsDefaultsWithoutEverMeaningUnbounded(t *testing.T) {
	t.Parallel()

	compact, err := domain.Limits{}.ResolveCompact()
	if err != nil {
		t.Fatalf("ResolveCompact: %v", err)
	}
	if compact.MaxPlaintext != domain.DefaultMaxPlaintext {
		t.Errorf("a zero plaintext ceiling resolved to %d, want %d", compact.MaxPlaintext, domain.DefaultMaxPlaintext)
	}
	if want := domain.DefaultMaxPlaintext + domain.CompactOverhead; compact.MaxCiphertext != want {
		t.Errorf("a zero ciphertext ceiling resolved to %d, want the derived %d", compact.MaxCiphertext, want)
	}

	framed, err := domain.Limits{}.ResolveFramed()
	if err != nil {
		t.Fatalf("ResolveFramed: %v", err)
	}
	// A framed stream costs a header plus one tag per frame, so its derived
	// ceiling is not the compact one — which is why there are two Resolves.
	if want := domain.FramedCiphertextLen(domain.DefaultMaxPlaintext); framed.MaxCiphertext != want {
		t.Errorf("framed ciphertext ceiling = %d, want %d", framed.MaxCiphertext, want)
	}
	if framed.MaxCiphertext == compact.MaxCiphertext {
		t.Error("the two formats derived the same ciphertext ceiling; one of them must be wrong")
	}

	// Raising the plaintext ceiling raises the derived ciphertext ceiling with
	// it, so a caller cannot end up unable to read back what it just wrote.
	raised, err := domain.Limits{MaxPlaintext: 8 << 20}.ResolveCompact()
	if err != nil {
		t.Fatalf("ResolveCompact: %v", err)
	}
	if want := int64(8<<20) + domain.CompactOverhead; raised.MaxCiphertext != want {
		t.Errorf("raised ciphertext ceiling = %d, want %d", raised.MaxCiphertext, want)
	}
}

// TestLimits_ResolveDoesNotWrapOnAnAbsurdCeiling covers the overflow guard:
// a caller that writes math.MaxInt64 meaning "effectively unlimited" must not
// end up with a derived ciphertext ceiling that wrapped negative and therefore
// refuses everything — or, worse, one that a comparison treats as satisfied.
func TestLimits_ResolveDoesNotWrapOnAnAbsurdCeiling(t *testing.T) {
	t.Parallel()

	for name, resolve := range map[string]func() (domain.Resolved, error){
		"compact": domain.Limits{MaxPlaintext: math.MaxInt64}.ResolveCompact,
		"framed":  domain.Limits{MaxPlaintext: math.MaxInt64}.ResolveFramed,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resolve()
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got.MaxCiphertext <= 0 {
				t.Fatalf("derived ciphertext ceiling = %d; the addition wrapped", got.MaxCiphertext)
			}
			if err := got.CheckCiphertext(1 << 30); err != nil {
				t.Errorf("a 1 GiB ciphertext under an effectively unlimited ceiling: %v", err)
			}
		})
	}
}

func TestResolved_BoundedAndTheCheckers(t *testing.T) {
	t.Parallel()

	bounded, err := domain.Limits{MaxPlaintext: 16}.ResolveCompact()
	if err != nil {
		t.Fatalf("ResolveCompact: %v", err)
	}
	if !bounded.Bounded() {
		t.Error("a configured ceiling reports Bounded() == false")
	}
	if err := bounded.CheckPlaintext(16); err != nil {
		t.Errorf("exactly at the ceiling: %v", err)
	}
	if err := bounded.CheckPlaintext(17); !errors.Is(err, domain.ErrLimitExceeded) {
		t.Errorf("one byte over: err = %v, want ErrLimitExceeded", err)
	}

	open, err := domain.Limits{MaxPlaintext: domain.Unlimited, MaxCiphertext: domain.Unlimited}.ResolveCompact()
	if err != nil {
		t.Fatalf("ResolveCompact: %v", err)
	}
	if open.Bounded() {
		t.Error("two Unlimited ceilings report Bounded() == true")
	}
	if err := open.CheckCiphertext(math.MaxInt64); err != nil {
		t.Errorf("Unlimited refused %d bytes: %v", int64(math.MaxInt64), err)
	}
}

func TestLimitError_NamesTheLimitAndMatchesTheSentinel(t *testing.T) {
	t.Parallel()

	err := error(&domain.LimitError{Limit: "max ciphertext", Max: 1024, Actual: 4096})
	if !errors.Is(err, domain.ErrLimitExceeded) {
		t.Error("a LimitError does not match ErrLimitExceeded")
	}
	var target *domain.LimitError
	if !errors.As(err, &target) {
		t.Fatal("errors.As did not recover the *LimitError")
	}
	for _, want := range []string{"max ciphertext", "1024", "4096"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}

	// An unknown actual length — which is what a streaming refusal has, since
	// it learns only that the next frame would cross the ceiling — must still
	// read sensibly rather than claim "-1 bytes".
	unknown := error(&domain.LimitError{Limit: "max plaintext", Max: 64, Actual: -1})
	if got := unknown.Error(); !strings.Contains(got, "more than 64") {
		t.Errorf("message for an unknown length = %q", got)
	}
}

func TestValidateStreamCeiling(t *testing.T) {
	t.Parallel()

	if err := domain.ValidateStreamCeiling(domain.Unlimited); err != nil {
		t.Errorf("Unlimited: %v", err)
	}
	if err := domain.ValidateStreamCeiling(1); err != nil {
		t.Errorf("1 byte: %v", err)
	}
	// Zero is refused here where a Limits field means "the default", because a
	// stream has no defensible default size.
	for _, n := range []int64{0, -2, math.MinInt64} {
		if err := domain.ValidateStreamCeiling(n); !errors.Is(err, domain.ErrInvalidLimit) {
			t.Errorf("%d: err = %v, want ErrInvalidLimit", n, err)
		}
	}
}

// TestDerivableLength covers rule 3's mechanism against every shape that can
// answer and one that cannot. Anything that cannot say is what makes a
// ceiling-bearing entry point refuse rather than read.
func TestDerivableLength(t *testing.T) {
	t.Parallel()

	payload := []byte("0123456789")

	t.Run("a Len method", func(t *testing.T) {
		n, ok := domain.DerivableLength(bytes.NewReader(payload))
		if !ok || n != 10 {
			t.Fatalf("DerivableLength(*bytes.Reader) = %d, %v; want 10, true", n, ok)
		}
	})

	t.Run("a Len method after a partial read", func(t *testing.T) {
		r := bytes.NewReader(payload)
		if _, err := r.Read(make([]byte, 4)); err != nil {
			t.Fatalf("Read: %v", err)
		}
		n, ok := domain.DerivableLength(r)
		if !ok || n != 6 {
			t.Fatalf("after reading 4 of 10 bytes: = %d, %v; want 6, true", n, ok)
		}
	})

	t.Run("an *os.File", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "payload")
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		f, err := os.Open(path) //nolint:gosec // a path this test just wrote inside t.TempDir()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close() //nolint:errcheck // read-only handle in a test

		n, ok := domain.DerivableLength(f)
		if !ok || n != 10 {
			t.Fatalf("DerivableLength(*os.File) = %d, %v; want 10, true", n, ok)
		}
	})

	t.Run("a bare Seeker, left where it was found", func(t *testing.T) {
		s := &seekerOnly{data: payload}
		if _, err := s.Read(make([]byte, 3)); err != nil {
			t.Fatalf("Read: %v", err)
		}
		n, ok := domain.DerivableLength(s)
		if !ok || n != 7 {
			t.Fatalf("DerivableLength(seeker) = %d, %v; want 7, true", n, ok)
		}
		rest, err := io.ReadAll(s)
		if err != nil {
			t.Fatalf("ReadAll after the probe: %v", err)
		}
		if string(rest) != "3456789" {
			t.Fatalf("the probe moved the reader: the rest is %q", rest)
		}
	})

	t.Run("an opaque reader cannot say", func(t *testing.T) {
		opaque := io.Reader(struct{ io.Reader }{bytes.NewReader(payload)})
		if n, ok := domain.DerivableLength(opaque); ok {
			t.Fatalf("an opaque reader reported a length of %d; a ceiling must fail closed on it", n)
		}
	})
}

// seekerOnly is a reader that can seek but has no Len and no Stat, which is
// the third path through the length probe.
type seekerOnly struct {
	data []byte
	off  int64
}

func (s *seekerOnly) Read(p []byte) (int, error) {
	if s.off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.off:])
	s.off += int64(n)
	return n, nil
}

func (s *seekerOnly) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.off = offset
	case io.SeekCurrent:
		s.off += offset
	case io.SeekEnd:
		s.off = int64(len(s.data)) + offset
	default:
		return 0, errors.New("bad whence")
	}
	return s.off, nil
}

func TestVersion_StringNamesTheShape(t *testing.T) {
	t.Parallel()

	for v, want := range map[domain.Version]string{
		domain.VersionFramed:  "1 (framed stream)",
		domain.VersionCompact: "2 (compact record)",
		domain.Version(9):     "unknown format version",
	} {
		if got := v.String(); got != want {
			t.Errorf("Version(%d).String() = %q, want %q", uint8(v), got, want)
		}
	}
}

// TestFramedCiphertextLen states the one place the formula is deliberately
// loose, so a future tightening is a decision rather than a surprise.
func TestFramedCiphertextLen(t *testing.T) {
	t.Parallel()

	header := int64(domain.FramedHeaderSize)
	cases := map[int64]int64{
		0:                      header + domain.TagSize,
		1:                      header + 1 + domain.TagSize,
		domain.FrameSize - 1:   header + domain.FrameSize - 1 + domain.TagSize,
		domain.FrameSize + 1:   header + domain.FrameSize + 1 + 2*domain.TagSize,
		3*domain.FrameSize + 1: header + 3*domain.FrameSize + 1 + 4*domain.TagSize,
	}
	for n, want := range cases {
		if got := domain.FramedCiphertextLen(n); got != want {
			t.Errorf("FramedCiphertextLen(%d) = %d, want %d", n, got, want)
		}
	}

	// At an exact multiple of FrameSize the writer produces one frame, not
	// two, so the formula is one tag generous. A ceiling that is 16 bytes
	// loose is the right side to be wrong on.
	exact := domain.FramedCiphertextLen(domain.FrameSize)
	if want := header + domain.FrameSize + 2*domain.TagSize; exact != want {
		t.Errorf("FramedCiphertextLen(FrameSize) = %d, want the documented %d", exact, want)
	}
}
