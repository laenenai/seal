// Command range encrypts a multi-frame SEAL1 object and reads a plaintext
// range that crosses a frame boundary. The size passed to the range reader is
// the authoritative stored ciphertext size from your metadata, not a Stat of
// the object store at read time.
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

	addr, err := seal.NewObjectAddress("tenant-42", "object-42")
	if err != nil {
		return err
	}

	// More than one frame's worth of plaintext, so the requested range crosses
	// the boundary between frame 0 and frame 1.
	plaintext := bytes.Repeat([]byte("0123456789"), 3*(seal.FrameSize/10))
	ciphertext, err := seal.EncryptObject(dek, addr, plaintext, seal.Limits{MaxPlaintext: seal.Unlimited})
	if err != nil {
		return err
	}

	// In production this size comes from the metadata row written at upload
	// time, not from a live Stat of the blob backend.
	size := int64(len(ciphertext))
	off := int64(seal.FrameSize - 6)
	length := int64(20)

	reader, err := seal.NewDecryptRangeReader(bytes.NewReader(ciphertext), size, dek, addr, off, length)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(os.Stdout, "range=%s\n", got); err != nil {
		return err
	}
	return nil
}
