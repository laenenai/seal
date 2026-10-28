// Command streaming encrypts a blob through the SEAL1 framed writer and
// decrypts it through the matching reader. It demonstrates the Close contract:
// the writer must be closed to seal the final frame, and the reader's Close
// error must be checked even after a successful Read.
package main

import (
	"bytes"
	"fmt"
	"io"
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

	addr, err := seal.NewObjectAddress("tenant-42", "blob-2026-10-28")
	if err != nil {
		return err
	}

	var ciphertext bytes.Buffer
	writer, err := seal.NewEncryptWriter(&ciphertext, dek, addr)
	if err != nil {
		return err
	}
	for _, chunk := range [][]byte{[]byte("hello "), []byte("streaming "), []byte("world")} {
		if _, err := writer.Write(chunk); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}

	reader, err := seal.NewDecryptReader(bytes.NewReader(ciphertext.Bytes()), dek, addr, seal.Unlimited)
	if err != nil {
		return err
	}
	plaintext, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}

	if _, err := fmt.Fprintf(os.Stdout, "plaintext=%s\n", plaintext); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "ciphertext_bytes=%d\n", ciphertext.Len()); err != nil {
		return err
	}
	return nil
}
