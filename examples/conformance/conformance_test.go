// Package conformance_test shows how a consumer runs the exported seal
// conformance suites against an implementation. In a real adapter, return your
// own implementation from the factory instead of seal.Compact()/seal.Framed().
package conformance_test

import (
	"testing"

	"github.com/laenenai/seal"
	"github.com/laenenai/seal/sealtest"
)

func TestRecordSealerConformance(t *testing.T) {
	sealtest.RunRecordSealerSuite(t, func(_ *testing.T) seal.RecordSealer {
		return seal.Compact()
	})
}

func TestStreamSealerConformance(t *testing.T) {
	sealtest.RunStreamSealerSuite(t, func(_ *testing.T) seal.StreamSealer {
		return seal.Framed()
	})
}
