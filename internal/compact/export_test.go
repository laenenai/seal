package compact

import (
	"github.com/laenenai/keyring"

	"github.com/laenenai/seal/internal/domain"
)

// SealWithSaltForTest behaves exactly like Seal except the record's salt is the
// caller's instead of being drawn from crypto/rand. It exists only so the
// committed testdata/vectors.json fixtures could be generated once,
// deterministically, and so a test can prove what happens when a salt repeats.
//
// Production code must always go through Seal. A caller-chosen salt is a
// caller-chosen key and nonce: reusing one across two records is the single
// way to make this format unsafe, which is why the seam is test-only rather
// than an exported option with a warning.
func SealWithSaltForTest(
	dek keyring.DEK, addr domain.RecordAddress, plaintext, salt []byte, limits domain.Resolved,
) ([]byte, error) {
	return sealWithSalt(dek, addr, plaintext, salt, limits)
}

// RecordKeyForTest derives the per-record key a record with this salt is
// sealed under, so a test can name the needle when asserting that no rendering
// discloses it.
func RecordKeyForTest(dek keyring.DEK, salt []byte) (key, nonce []byte, err error) {
	return deriveRecordKey(dek, salt)
}
