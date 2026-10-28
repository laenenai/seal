// Command records encrypts and decrypts one small value as a compact SEAL2
// record, then shows that the same ciphertext no longer opens at another
// address.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dek, err := keyring.NewDEK()
	if err != nil {
		return err
	}
	defer dek.Destroy()

	addr, err := seal.NewRecordAddress("graph-42", "fact-7", "salary")
	if err != nil {
		return err
	}

	record, err := seal.EncryptRecord(dek, addr, []byte("50000"), seal.Limits{})
	if err != nil {
		return err
	}

	plaintext, err := seal.DecryptRecord(dek, addr, record, seal.Limits{})
	if err != nil {
		return err
	}

	// The same bytes at a different address are a decryption failure, not a
	// silently relocated value.
	otherAddr, err := seal.NewRecordAddress("graph-42", "fact-7", "bonus")
	if err != nil {
		return err
	}
	_, relocatedErr := seal.DecryptRecord(dek, otherAddr, record, seal.Limits{})

	if _, err := fmt.Fprintf(os.Stdout, "plaintext=%s\n", plaintext); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "relocated=%v\n", errors.Is(relocatedErr, seal.ErrCorrupt)); err != nil {
		return err
	}
	return nil
}
