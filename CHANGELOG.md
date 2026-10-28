# Changelog

All notable changes to `seal` are recorded here. The format is human-readable;
versions follow SemVer with the pre-1.0 rule that a minor release may break the
API. See `UPGRADING.md` for migration steps.

## Unreleased

This is the API-compatibility tooling migration. It does not change the wire
format or the importable Go API.

### Breaking changes

- None. `apidiff` against `v0.2.0` reports no incompatible API changes.

### Tooling

- **Removed the `api.txt` golden-file pattern.** `api.txt`, `api_test.go`,
  `TestAPIGolden`, the `-update-api` flag, and `mise run api` are gone. The
  golden file captured implementation declarations, including internal
  packages, and did not prove consumer compatibility.
- **Added `scripts/api-diff.sh` and `mise run api-diff`.** `apidiff` compares
  the current importable API with the last root tag (`v0.2.0`), ignores
  `internal/...`, and reports incompatible changes. Pre-1.0 it reports without
  failing; `API_DIFF_STRICT=1` makes incompatibilities fail the gate.
- **Added `mise run release-check` and a release workflow.** `gorelease`
  validates a clean tagged release against the latest published version and the
  release body comes from this changelog.
- **Added `mise run vuln` and `mise run generate-check`.** `check` now depends
  on `fmt-check`, `lint`, `build`, `test-all`, `generate-check`, `vuln`, and
  `api-diff`.
- **CI now checks out full tags and runs `mise run check`.** Tool versions live
  only in `mise.toml`; the workflow no longer pins gofumpt or golangci-lint a
  second time.

### Examples and docs

- Added `examples/` with runnable compact-record, streaming, ranged-read, and
  conformance-suite examples, plus `examples/README.md` covering use-case
  selection and best practices.
- Added godoc examples for `EncryptRecord`, `NewDecryptReader`, and
  `NewDecryptRangeReader`; `go test` compiles and runs them.

## v0.2.0 — 2026-10-27

- Additive conformance-suite coverage: a three-frame fixture now reaches a
  dropped final frame, a dropped interior frame, and two swapped frames; the
  bit-flip sweep is sampled with a guard against sample growth.
- Added `NoSecretLeaksInAnyError` to exercise real failure paths and assert
  that no error string carries plaintext or key material.
- Added `sealtest.NewDEK` for consumer test wiring.
- No wire-format or public-API change.

## v0.1.0 — 2026-10-24

- First release. SEAL1 framed streaming AEAD (format version 1), extracted from
  `cas/internal/crypto`, and the new SEAL2 compact record (format version 2),
  in one version space with committed test vectors.
- Five size-ceiling rules, address-bound AAD, conformance suites in `sealtest`,
  and redaction discipline on every returned value.
- Deliberately not wire-compatible with `cas/internal/crypto`.
