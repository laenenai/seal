package domain

// This file is the module's version registry: one numbered space covering
// both wire shapes, and the constants each shape's layout is made of.
//
// # One version space, not one per shape
//
// A format version here names a (shape, revision) pair, and the next change to
// either shape takes the next number in this one space rather than a second
// counter of its own. So "format version 1" is the framed stream as CAS
// shipped it and "format version 2" is the compact record; a future reframing
// of the framed format is version 3, not "CASF2". The cost of one space is
// that the numbers no longer read as "revision 1 of the framed format"; what
// it buys is that a version number is unambiguous on its own, which is what
// matters when it is the thing bound into an AEAD tag and the thing a stored
// row records.
//
// Every version is bound into its own additional authenticated data, which is
// what a shared magic prefix would have been for: a ciphertext written under
// one version cannot be opened as another, because the version is part of what
// every tag was computed over. See AAD construction in internal/framed and
// internal/compact, and docs/format.md for the registry in prose.
//
// # Why the framed format's magic still says CASF1
//
// FramedMagic is five ASCII bytes spelling "CASF1", which names the module the
// format was extracted from rather than the module that now owns it. That is
// deliberate and it is the one place this module keeps a spelling it would not
// have chosen.
//
// The framed format arrives here with a committed format document and
// testdata/vectors.json, and a test that decrypts that committed ciphertext
// byte for byte. That test is the only mechanism that stops the document and
// the code drifting silently, and it is worth more than the spelling: renaming
// the magic changes every frame's additional authenticated data, which changes
// every committed tag, which means regenerating the vectors — and a module
// that regenerates its vectors has thrown the property away and kept the file.
//
// The middle path — accept "CASF1" on read, write a renamed magic on new
// streams — was considered and rejected. It is two formats for one job, a
// migration no consumer asked for, and a doubled test matrix, bought with a
// nicer spelling. A wire magic is a historical constant in every format that
// has one; "GIF89a" does not name a company either.

// Version is a format version in the module's single version space. It is one
// byte on the wire wherever it appears there, and is bound into every AEAD
// tag whether or not it is stored.
type Version uint8

const (
	// VersionFramed is format version 1: the framed streaming AEAD, extracted
	// verbatim from cas/internal/crypto. Its wire discriminator is the
	// five-byte FramedMagic at the head of the stream header, not a Version
	// byte; the number is what the registry and the AAD know it by.
	VersionFramed Version = 1

	// VersionCompact is format version 2: the compact record for small whole
	// values. Its wire discriminator is a single leading byte holding this
	// value, which is also the format's version in this registry — the same
	// number in both roles, on purpose, so there is nothing to keep in step.
	VersionCompact Version = 2
)

// String renders a version as the registry spells it, for an error or a log
// line that has to say which format a ciphertext claims to be.
func (v Version) String() string {
	switch v {
	case VersionFramed:
		return "1 (framed stream)"
	case VersionCompact:
		return "2 (compact record)"
	default:
		return "unknown format version"
	}
}

// Framed format (version 1) constants. These describe the committed CASF1
// wire format and must not change without changing docs/format.md and the
// committed vectors together, deliberately — silent drift here means
// previously stored ciphertext becomes unreadable.
const (
	// FramedMagic is the five ASCII bytes at the head of every framed stream.
	// See this file's doc comment for why it still spells CASF1.
	FramedMagic = "CASF1"

	// FramedSaltSize is the size of a framed stream's per-stream random salt.
	FramedSaltSize = 16

	// FramedHeaderSize is the fixed header size: magic, frame size as a
	// big-endian uint32, and salt.
	FramedHeaderSize = len(FramedMagic) + 4 + FramedSaltSize

	// FramedKeyInfo is the HKDF info string the per-stream frame key is
	// derived under. It is part of the wire format: changing it makes every
	// stored stream undecryptable.
	FramedKeyInfo = "CASF1 frame key"

	// FrameSize is the number of plaintext bytes sealed into every frame
	// except possibly the last, which may be shorter (and is always present,
	// even if empty, so a zero-byte object is one short final frame rather
	// than zero frames).
	FrameSize = 1 << 20

	// MinFrameSize and MaxFrameSize bound the frame_size a decoder will
	// accept from a stream's header. The floor keeps a corrupted or hostile
	// header from forcing the decoder to process an enormous number of
	// vanishingly small frames; the ceiling bounds the memory needed to
	// buffer one frame.
	//
	// This bound exists purely to bound decoder resource use and authenticates
	// nothing. What makes the header effectively authenticated is that the
	// entire header is bound into every frame's AAD. They are two mechanisms
	// and docs/format.md keeps them apart, because that is the distinction a
	// rewrite loses.
	MinFrameSize = 64
	MaxFrameSize = 8 * 1024 * 1024 // 8 MiB
)

// Compact format (version 2) constants.
const (
	// CompactSaltSize is the size of a compact record's per-record random
	// salt. It is 128 bits because the salt is the whole of the per-record
	// key's uniqueness, so the number of records one DEK may seal is bounded
	// by collisions in this space rather than in a 96-bit nonce space. The
	// arithmetic is in docs/format.md.
	CompactSaltSize = 16

	// CompactKeyInfo is the HKDF info string a compact record's per-record key
	// and nonce are derived under, in one expansion. It names the format
	// version, so the derivation is domain-separated from the framed format's
	// even when the same DEK is used for both.
	CompactKeyInfo = "SEAL2 record key"

	// CompactPrefixSize is the unencrypted prefix of a compact record: one
	// version byte and the salt. The whole prefix is bound into the record's
	// AAD, the same way the framed format binds its whole header, so there is
	// no "which prefix bytes are covered" question to work out.
	CompactPrefixSize = 1 + CompactSaltSize

	// CompactOverhead is what a compact record costs over its plaintext: 33
	// bytes, against 41 for a single-frame framed stream (a 25-byte header
	// plus a 16-byte tag). On a 1 MiB blob the difference is nothing; on a
	// 20-byte fact literal it is 165% overhead against 205%, which is the
	// honest size of the win — the derived nonce and the absent framing save
	// eight bytes, not an order of magnitude. What actually makes the compact
	// record the right tool for tens of millions of short values is that it
	// costs one AEAD operation and no framing state, not that it is small.
	CompactOverhead = CompactPrefixSize + TagSize
)

// NonceSize is crypto/cipher's standard GCM nonce size, and TagSize its
// standard tag size. Both formats use both.
const (
	NonceSize = 12
	TagSize   = 16
)

// CompactCiphertextLen returns the number of bytes a compact record of n
// plaintext bytes occupies.
func CompactCiphertextLen(n int64) int64 { return n + CompactOverhead }

// FramedCiphertextLen returns the number of bytes a framed stream of n
// plaintext bytes occupies at the production frame size: the header, the
// plaintext, and one tag per frame.
//
// It is exact except when n is an exact multiple of FrameSize, where it is one
// tag generous — the writer only seals a full buffer as a non-final frame once
// more data is known to follow, so a plaintext of exactly FrameSize bytes is
// one frame and not two. A ceiling that is 16 bytes loose is the right side to
// be wrong on; a ceiling that is 16 bytes tight would refuse a stream the
// encoder had just produced.
func FramedCiphertextLen(n int64) int64 {
	frames := n/FrameSize + 1
	return int64(FramedHeaderSize) + n + frames*TagSize
}

// DEKSize is the key size both formats derive down to, and the size of a
// keyring DEK. It is restated here rather than imported so that this package
// — which must not depend on a key manager — can state the AES-256 key size
// the formats are built on.
const DEKSize = 32

// Redacted is the placeholder every rendering of a type holding derived key
// material yields. It is the same literal keyring uses, so a consumer's own
// log scrubbing and its own tests can assert against one string across both
// modules.
const Redacted = "[REDACTED]"

// RedactedAs returns the fixed placeholder for a type named name: it
// identifies the type and carries nothing else — no part of the material, no
// fingerprint, and no length.
//
// Naming the type is load-bearing rather than decorative. A log line reading
// "[REDACTED]" tells an operator nothing; one reading
// "seal.EncryptWriter([REDACTED])" says what was at that position, which is
// what makes the line diagnosable at all. The type is not the secret.
func RedactedAs(name string) string { return name + "(" + Redacted + ")" }
