package compact_test

// One-off generator for testdata/vectors.json, kept out of the build by a flag
// that is off by default. It runs once, when the format is first committed, and
// then never again: the committed ciphertext is the artifact, and the whole
// point of the vector test is to fail when the wire format changes rather than
// to be refreshed.
//
// It is in the repository rather than in a scratch directory so that the
// provenance of the committed bytes is auditable — which fixed DEK, which
// fixed salt, which address — not so that a failing vector has somewhere to be
// regenerated from.

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/compact"
	"github.com/laenenai/seal/internal/domain"
)

var writeVectors = flag.Bool("write-compact-vectors", false,
	"regenerate testdata/vectors.json; see gen_vectors_test.go before using this")

func TestGenerateCommittedVectors(t *testing.T) {
	if !*writeVectors {
		t.Skip("off by default: the committed vectors are an artifact, not an output")
	}

	type vector struct {
		Name          string   `json:"name"`
		DEKHex        string   `json:"dek_hex"`
		SaltHex       string   `json:"salt_hex"`
		Address       []string `json:"address"`
		PlaintextHex  string   `json:"plaintext_hex"`
		CiphertextHex string   `json:"ciphertext_hex"`
	}

	cases := []struct {
		name    string
		dekHex  string
		saltHex string
		address []string
		plain   []byte
	}{
		{
			name:    "twenty_byte_fact_literal",
			dekHex:  "3f1d8c04b67a29e5d1430fb8c7265ae90b4d8821f3c6957ea0d412b7683f5c19",
			saltHex: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
			address: []string{"graph-01HZX0COMPACTGRAPH00", "01HZX0COMPACTFACT000000000", "salary"},
			plain:   []byte("147500 EUR per year"),
		},
		{
			name:    "empty_value",
			dekHex:  "9e2f71aa05c3b84d6612ff8370d9e4c1528b0a7f3d6e95c2418b7f06da35e9c4",
			saltHex: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
			address: []string{"graph-01HZX0COMPACTGRAPH00", "01HZX0COMPACTFACT000000001", "middle_name"},
			plain:   []byte{},
		},
		{
			name:    "single_component_address_binary_value",
			dekHex:  "c0ffee00deadbeef1122334455667788998877665544332211aabbccddeeff00",
			saltHex: "ffeeddccbbaa99887766554433221100",
			address: []string{"blob-01HZX0COMPACTBLOB0000"},
			plain:   []byte{0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff, 0x00, 0x7f, 0x80},
		},
	}

	out := struct {
		Comment string   `json:"_comment"`
		Vectors []vector `json:"vectors"`
	}{
		Comment: strings.Join([]string{
			"Committed format-version-2 (compact record) vectors.",
			"Generated once, deliberately, by gen_vectors_test.go -write-compact-vectors, each with a fixed DEK",
			"and a fixed salt so the ciphertext is reproducible; see docs/format.md, 'Test vectors'.",
			"TestVectors_MatchCommittedTestdata decrypts each entry's ciphertext_hex directly. It must never be",
			"replaced by re-encrypting plaintext_hex and comparing, since the whole point is to catch a silent",
			"wire-format change that a round trip cannot. If a committed ciphertext stops decrypting, that is a",
			"real failure, not a vector to refresh.",
			"Three vectors are committed because one cannot discriminate: a single-component address does not",
			"exercise the component count in the AAD, an empty value does not exercise the ciphertext body, and a",
			"value whose bytes are all printable would not catch a plaintext that was somehow text-normalised.",
			"salt_hex is recorded only so the fixture's provenance is auditable; the decoder reads the salt from",
			"the record itself, as every real reader does.",
		}, " "),
	}

	for _, c := range cases {
		dekBytes, err := hex.DecodeString(c.dekHex)
		if err != nil {
			t.Fatalf("%s: decode dek: %v", c.name, err)
		}
		dek, err := keyring.DEKFrom(dekBytes)
		if err != nil {
			t.Fatalf("%s: DEKFrom: %v", c.name, err)
		}
		salt, err := hex.DecodeString(c.saltHex)
		if err != nil {
			t.Fatalf("%s: decode salt: %v", c.name, err)
		}
		addr, err := domain.NewRecordAddress(c.address...)
		if err != nil {
			t.Fatalf("%s: NewRecordAddress: %v", c.name, err)
		}
		limits, err := domain.Limits{}.ResolveCompact()
		if err != nil {
			t.Fatalf("%s: Resolve: %v", c.name, err)
		}
		record, err := compact.SealWithSaltForTest(dek, addr, c.plain, salt, limits)
		if err != nil {
			t.Fatalf("%s: SealWithSaltForTest: %v", c.name, err)
		}
		dek.Destroy()

		out.Vectors = append(out.Vectors, vector{
			Name:          c.name,
			DEKHex:        c.dekHex,
			SaltHex:       c.saltHex,
			Address:       c.address,
			PlaintextHex:  hex.EncodeToString(c.plain),
			CiphertextHex: hex.EncodeToString(record),
		})
	}

	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile("testdata/vectors.json", append(blob, '\n'), 0o600); err != nil {
		t.Fatalf("write testdata/vectors.json: %v", err)
	}
	t.Log("testdata/vectors.json written")
}
