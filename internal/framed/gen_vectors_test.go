package framed_test

// One-off generator for testdata/vectors.json, kept out of the build by a flag
// that is off by default. It runs when the wire format deliberately changes and
// at no other time: the committed ciphertext is the artifact, and the whole
// point of the vector test is to fail when the format changes rather than to be
// refreshed.
//
// It is in the repository, mirroring internal/compact's, so that the provenance
// of the committed bytes is auditable — which fixed DEK, which fixed salt,
// which frame size, which address — and so that a reviewer can reproduce the
// committed file rather than take it on trust. It is not here so that a failing
// vector has somewhere to be regenerated from.
//
// It has been run exactly once, when the format's magic and HKDF info string
// were renamed from CAS's spelling to SEAL1. The DEKs, salts, frame sizes,
// tenant and content addresses below are the ones CAS's original fixture used,
// unchanged, so that what changed between the two committed files is the wire
// format and little else — the only other change is the first vector's
// plaintext, an ASCII sentence that used to name CAS.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/domain"
	"github.com/laenenai/seal/internal/framed"
)

var writeVectors = flag.Bool("write-framed-vectors", false,
	"regenerate testdata/vectors.json; see gen_vectors_test.go before using this")

func TestGenerateCommittedVectors(t *testing.T) {
	if !*writeVectors {
		t.Skip("off by default: the committed vectors are an artifact, not an output")
	}

	type contentAddress struct {
		Algo string `json:"algo"`
		Hex  string `json:"hex"`
	}
	type vector struct {
		Name          string         `json:"name"`
		DEKHex        string         `json:"dek_hex"`
		SaltHex       string         `json:"salt_hex"`
		FrameSize     int            `json:"frame_size"`
		Tenant        string         `json:"tenant_id"`
		Address       contentAddress `json:"content_address"`
		PlaintextHex  string         `json:"plaintext_hex"`
		CiphertextHex string         `json:"ciphertext_hex"`
	}

	const fixedTenant = "01HZX0VECTORFIXEDTENANTID00"

	// The three-frame vector's plaintext is 0x00..0x9d: two full 64-byte frames
	// and a 30-byte short final one.
	threeFrames := make([]byte, 158)
	for i := range threeFrames {
		threeFrames[i] = byte(i)
	}

	cases := []struct {
		name      string
		dekHex    string
		saltHex   string
		frameSize int
		addrHex   string
		plain     []byte
	}{
		{
			name:      "single_frame_final_at_index_0",
			dekHex:    "7a1c9e3f5b2d4a6081e4f7c93b5d2a1087f6e5d4c3b2a190807f6e5d4c3b2a19",
			saltHex:   "0102030405060708090a0b0c0d0e0f10",
			frameSize: domain.FrameSize,
			addrHex:   "0000000000000000000000000000000000000000000000000000000000000001",
			plain:     []byte("SEAL stream format vector: the quick brown fox jumps over the lazy dog."),
		},
		{
			name:      "three_frames_nonfinal_and_short_final",
			dekHex:    "c552b1188418271874a1b31b7cde54827b891a34faeb2510deed29ee90343d9a",
			saltHex:   "80162a32f2f36f7fefba8d1a46e8fb59",
			frameSize: 64,
			addrHex:   "0000000000000000000000000000000000000000000000000000000000000002",
			plain:     threeFrames,
		},
	}

	out := struct {
		Comment string   `json:"_comment"`
		Vectors []vector `json:"vectors"`
	}{
		Comment: strings.Join([]string{
			"Committed format-version-1 (framed stream) vectors.",
			"Generated once, deliberately, by gen_vectors_test.go -write-framed-vectors, each with a fixed DEK",
			"and a fixed salt so the ciphertext is reproducible; see docs/format.md, 'Test vectors'.",
			"TestVectors_MatchCommittedTestdata decrypts each entry's ciphertext_hex directly. It must never be",
			"replaced by re-encrypting plaintext_hex and comparing, since the whole point is to catch a silent",
			"wire-format change that a round trip cannot. If a committed ciphertext stops decrypting, that is a",
			"real failure, not a vector to refresh.",
			"More than one vector is committed deliberately: a single small vector whose only frame is index 0",
			"with final=true cannot distinguish several wire format changes (nonce/AAD index endianness,",
			"final-flag encoding, wire stride, the finality rule) from the correct format, because index 0 is",
			"all-zeros and final=true is the only branch it exercises.",
			"These bytes are NOT the ones cas/internal/crypto wrote. The magic and the HKDF info string were",
			"renamed from CASF1 to SEAL1 when the format was extracted, which changes both the frame key and",
			"every tag, so CAS's ciphertext does not decrypt here and this fixture was regenerated once for",
			"that rename. The DEKs, salts, frame sizes, tenant and content addresses are CAS's fixture",
			"unchanged, so the diff that regenerated this file shows the format changing and little else; the",
			"only other change is the first vector's plaintext, an ASCII sentence that used to name CAS.",
			"salt_hex and frame_size are recorded only so the fixture's provenance is auditable; the decoder",
			"reads both from the header, as every real reader does.",
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
		addr, err := domain.NewObjectAddress(fixedTenant, "sha256:"+c.addrHex)
		if err != nil {
			t.Fatalf("%s: NewObjectAddress: %v", c.name, err)
		}

		var buf bytes.Buffer
		w, err := framed.NewEncryptWriterForTest(&buf, dek, addr, bytes.NewReader(salt), c.frameSize)
		if err != nil {
			t.Fatalf("%s: NewEncryptWriterForTest: %v", c.name, err)
		}
		if _, err := w.Write(c.plain); err != nil {
			t.Fatalf("%s: Write: %v", c.name, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s: Close: %v", c.name, err)
		}
		dek.Destroy()

		out.Vectors = append(out.Vectors, vector{
			Name:          c.name,
			DEKHex:        c.dekHex,
			SaltHex:       c.saltHex,
			FrameSize:     c.frameSize,
			Tenant:        fixedTenant,
			Address:       contentAddress{Algo: "sha256", Hex: c.addrHex},
			PlaintextHex:  hex.EncodeToString(c.plain),
			CiphertextHex: hex.EncodeToString(buf.Bytes()),
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
