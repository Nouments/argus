package buffer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteEncryptedAppend encrypts data with AES-256-GCM and appends as hex lines to file
func WriteEncryptedAppend(dir, filename string, key []byte, data []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: %d", len(key))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, data, nil)
	// store nonce||ct as hex line
	out := append(nonce, ct...)
	f, err := os.OpenFile(filepath.Join(dir, filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(out) + "\n"); err != nil {
		return err
	}
	return nil
}

// ReadAndDecryptAll reads all lines, decrypts using key and returns slices of plaintext
func ReadAndDecryptAll(path string, key []byte) ([][]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := make([][]byte, 0)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		raw, err := hex.DecodeString(string(line))
		if err != nil {
			return nil, err
		}
		nonceSize := gcm.NonceSize()
		if len(raw) < nonceSize {
			return nil, fmt.Errorf("ciphertext too short")
		}
		nonce := raw[:nonceSize]
		ct := raw[nonceSize:]
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, err
		}
		lines = append(lines, pt)
	}
	return lines, nil
}

func splitLines(b []byte) [][]byte {
	out := [][]byte{}
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// ReadRawLines returns the raw hex-encoded lines from the file (no decoding)
func ReadRawLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out, nil
}

// OverwriteRawLines overwrites the file with the provided raw hex lines
func OverwriteRawLines(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}
