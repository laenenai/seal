package seal_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/laenenai/keyring"

	"github.com/laenenai/seal"
)

func ExampleEncryptRecord() {
	if err := encryptRecordExample(); err != nil {
		log.Fatal(err)
	}
	// Output: 50000
}

func encryptRecordExample() error {
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

	_, err = fmt.Fprintln(os.Stdout, string(plaintext))
	return err
}

func ExampleNewDecryptReader() {
	if err := decryptReaderExample(); err != nil {
		log.Fatal(err)
	}
	// Output: hello
}

func decryptReaderExample() error {
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
	if _, err := writer.Write([]byte("hello")); err != nil {
		return err
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

	_, err = fmt.Fprintln(os.Stdout, string(plaintext))
	return err
}

func ExampleNewDecryptRangeReader() {
	if err := decryptRangeReaderExample(); err != nil {
		log.Fatal(err)
	}
	// Output: 5678901234
}

func decryptRangeReaderExample() error {
	dek, err := keyring.NewDEK()
	if err != nil {
		return err
	}
	defer dek.Destroy()

	addr, err := seal.NewObjectAddress("tenant-42", "object-42")
	if err != nil {
		return err
	}

	plaintext := bytes.Repeat([]byte("0123456789"), 10)
	ciphertext, err := seal.EncryptObject(dek, addr, plaintext, seal.Limits{})
	if err != nil {
		return err
	}

	reader, err := seal.NewDecryptRangeReader(
		bytes.NewReader(ciphertext), int64(len(ciphertext)), dek, addr, 5, 10,
	)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(os.Stdout, string(got))
	return err
}
