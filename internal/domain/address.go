package domain

// This file declares the two address types, and they are the reason this
// module exists rather than a convenience over crypto/cipher.
//
// # The AAD binding is the point, not an optimisation
//
// An address is what the ciphertext's additional authenticated data binds to.
// Without it, an encrypted value is confidential and nothing more: an
// encrypted salary can be relocated onto another row — by a bug, or by anyone
// with database write access — and will decrypt cleanly to the wrong answer,
// because nothing in the ciphertext says where it belonged. With it,
// relocation is a decryption failure. That is the whole claim, and it is
// recorded as leak channel #17 in the kgs design.
//
// The framed format binds (tenant, object); the compact record generalises
// that to an ordered list of components, which is how a kgs attribute value
// binds to (graph, fact id, attribute). Confidentiality without integrity of
// placement is not enough.
//
// # Why both are opaque structs
//
// A named string type is unforgeable against mixing — you cannot pass an
// object id where a tenant id is wanted — but not against construction: any
// package could write ObjectAddress{Tenant: "x"} and obtain a value that
// never went through validation. Here that is not an acceptable trade,
// because the address is an input to every AEAD tag: a component carrying a
// NUL, a newline or a path separator reaches the tag as itself, and the same
// string then reaches a database key, an object-store name and a log field,
// where the safe set is the intersection of what all of them accept rather
// than the union.
//
// The cost, stated rather than discovered: an address cannot be a map key
// written as a literal, cannot be built from a database column without going
// through its constructor, and must never be given sql.Scanner or
// driver.Valuer — those methods are exported, so any package could then
// construct one from an arbitrary string, which destroys exactly the property
// the type exists for.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxAddressComponentLen bounds one address component. Generous relative to
// any real identifier (a ULID is 26 bytes, a "sha256:<64 hex>" content
// address is 71) and present to reject a deliberately oversized value before
// it becomes part of every tag's input and of a database key.
const maxAddressComponentLen = 256

// maxRecordAddressComponents bounds how many components a record address may
// carry. kgs needs three — graph, fact id, attribute — and the bound exists so
// a caller cannot assemble an address whose AAD costs more than the record it
// protects.
const maxRecordAddressComponents = 16

// ObjectAddress is what a framed stream's ciphertext is bound to: exactly one
// object of exactly one tenant. A frame sealed for one object can never be
// decrypted, spliced, or replayed into another object, even another object
// belonging to the same tenant — any difference in either component changes
// every frame's AAD and makes every frame fail to authenticate.
//
// It carries exactly two components and no more, and that is a wire-format
// constraint rather than a modelling preference. Version 1's AAD encodes the
// two components length-prefixed with no count (see AppendAAD), which is
// injective only because the number of components is fixed by the format; a
// third component would make the encoding ambiguous, and adding a count to
// close that would change every committed tag.
type ObjectAddress struct {
	tenant string
	object string
}

// NewObjectAddress returns the address a framed stream binds to, or
// ErrInvalidAddress if either component is not safe to bind.
//
// object is the caller's canonical name for the object, in whatever spelling
// the caller will present again at decrypt time — CAS passes a content
// address's canonical "<algo>:<hex>" form. This module never parses it; it
// only requires that the same bytes come back, which is the property that
// makes the binding mean anything.
func NewObjectAddress(tenant, object string) (ObjectAddress, error) {
	if err := validateComponent("tenant", tenant); err != nil {
		return ObjectAddress{}, err
	}
	if err := validateComponent("object", object); err != nil {
		return ObjectAddress{}, err
	}
	return ObjectAddress{tenant: tenant, object: object}, nil
}

// Tenant returns the tenant component unchanged. Neither component is a
// secret: an address names a place without describing what is kept there.
func (a ObjectAddress) Tenant() string { return a.tenant }

// Object returns the object component unchanged.
func (a ObjectAddress) Object() string { return a.object }

// IsZero reports whether a names nothing, which is the zero value and is
// refused by every entry point.
func (a ObjectAddress) IsZero() bool { return a.tenant == "" && a.object == "" }

// String renders the address as "tenant/object" for a log line or an error.
func (a ObjectAddress) String() string { return a.tenant + "/" + a.object }

// AppendAAD appends the address's contribution to a frame's additional
// authenticated data: each component length-prefixed with a big-endian
// uint32, tenant first.
//
// There is no component count, and there must not be one: this is byte for
// byte what CAS's committed vectors were sealed under, and the encoding is
// unambiguous without a count only because version 1 fixes the number of
// components at two. The length prefixes are what make it injective at that
// fixed arity — there is no pair of (tenant, object) values that could be
// reinterpreted as a different split of the same bytes.
func (a ObjectAddress) AppendAAD(dst []byte) []byte {
	dst = appendLengthPrefixed(dst, a.tenant)
	return appendLengthPrefixed(dst, a.object)
}

// RecordAddress is what a compact record's ciphertext is bound to: an ordered
// list of components naming the one place that value belongs. A kgs attribute
// value binds to (graph, fact id, attribute); what the components mean is the
// caller's business and this module never learns it.
//
// Order is significant and is part of the binding: ("a", "b") and ("b", "a")
// are different addresses, so a value cannot be moved between two columns
// whose names happen to be each other's.
type RecordAddress struct {
	parts []string
}

// NewRecordAddress returns the address a compact record binds to, or
// ErrInvalidAddress if there are no components, too many, or any one of them
// is not safe to bind.
//
// At least one component is required: an address that names nothing binds
// nothing, and a record bound to nothing is a record that can be relocated
// anywhere, which is the failure this type exists to prevent. There is no
// "unaddressed record" convenience, deliberately — a caller that genuinely
// has nothing to bind to should say so by passing a constant, in the open.
func NewRecordAddress(parts ...string) (RecordAddress, error) {
	if len(parts) == 0 {
		return RecordAddress{}, fmt.Errorf("%w: a record address needs at least one component", ErrInvalidAddress)
	}
	if len(parts) > maxRecordAddressComponents {
		return RecordAddress{}, fmt.Errorf("%w: %d components, maximum %d",
			ErrInvalidAddress, len(parts), maxRecordAddressComponents)
	}
	for i, p := range parts {
		if err := validateComponent(fmt.Sprintf("component %d", i), p); err != nil {
			return RecordAddress{}, err
		}
	}
	// Cloned so a caller that reuses its slice cannot mutate an address that
	// has already been bound into a tag.
	return RecordAddress{parts: append(make([]string, 0, len(parts)), parts...)}, nil
}

// Parts returns a copy of the address's components, in order.
func (a RecordAddress) Parts() []string {
	return append(make([]string, 0, len(a.parts)), a.parts...)
}

// IsZero reports whether a names nothing, which is the zero value and is
// refused by every entry point.
func (a RecordAddress) IsZero() bool { return len(a.parts) == 0 }

// String renders the address as "a/b/c" for a log line or an error. The
// components cannot contain a slash, so this rendering is unambiguous.
func (a RecordAddress) String() string { return strings.Join(a.parts, "/") }

// AppendAAD appends the address's contribution to a compact record's
// additional authenticated data: the component count as a big-endian uint32,
// then each component length-prefixed with a big-endian uint32.
//
// The count is encoded here and is not in ObjectAddress.AppendAAD, and the
// difference is not an inconsistency. The framed format fixes its arity at
// two, so length prefixes alone are injective; a record address has a
// variable number of components, and length-prefixed concatenation without a
// count is not injective across differing arities. Encoding the count makes
// it so, which is what stops ("a", "bc") and ("abc",) from being arranged
// into the same bytes.
func (a RecordAddress) AppendAAD(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(a.parts))) //nolint:gosec // bounded by maxRecordAddressComponents
	for _, p := range a.parts {
		dst = appendLengthPrefixed(dst, p)
	}
	return dst
}

// appendLengthPrefixed appends s preceded by its length as a big-endian
// uint32.
func appendLengthPrefixed(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s))) //nolint:gosec // bounded by maxAddressComponentLen
	return append(dst, s...)
}

// validateComponent reports whether s is safe to bind into additional
// authenticated data and to carry everywhere the same value goes: a single
// non-empty component, no longer than maxAddressComponentLen, valid UTF-8,
// free of path separators, null bytes, control characters and surrounding
// whitespace, and not a relative path element.
//
// The rules are deliberately stricter than the AEAD needs — GCM would bind
// any byte string — because the same component is a database key, an
// object-store name and an audit-log field, and the safe set is the
// intersection of what all of those accept rather than the union. Widening it
// later is a reviewed change to this one function rather than a surprise in
// one caller. They are the same rules keyring applies to a KEK id and a key
// id, for the same reason.
func validateComponent(label, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidAddress, label)
	}
	if len(s) > maxAddressComponentLen {
		return fmt.Errorf("%w: %s is %d bytes, maximum %d", ErrInvalidAddress, label, len(s), maxAddressComponentLen)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidAddress, label)
	}
	if s == "." || strings.Contains(s, "..") {
		return fmt.Errorf("%w: %s is a relative path element", ErrInvalidAddress, label)
	}
	if strings.ContainsAny(s, "/\\\x00") {
		return fmt.Errorf("%w: %s contains a path separator or null byte", ErrInvalidAddress, label)
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("%w: %s has leading or trailing whitespace", ErrInvalidAddress, label)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%w: %s contains a control or whitespace character", ErrInvalidAddress, label)
		}
	}
	return nil
}
