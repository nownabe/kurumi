package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	privateKeyPrefix = "kurumi-private-key-v1:"
	publicKeyPrefix  = "kurumi-public-key-v1:"
	maxKeyFileSize   = 4096
)

func encodeKey(prefix string, key []byte) string {
	return prefix + base64.StdEncoding.EncodeToString(key)
}

// decodeKeyLine returns the 32 key bytes; the caller must clear them.
func decodeKeyLine(line []byte, prefix string) ([]byte, error) {
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return nil, fmt.Errorf("key does not start with %q", prefix)
	}
	b64 := line[len(prefix):]
	key := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Strict().Decode(key, b64)
	if err != nil || n != 32 || bytes.ContainsAny(b64, "\r\n") {
		clear(key)
		return nil, errors.New("key must be one line of base64 encoding exactly 32 bytes")
	}
	return key[:n], nil
}

func parsePublicKey(line []byte) (*ecdh.PublicKey, error) {
	b, err := decodeKeyLine(line, publicKeyPrefix)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

func parsePrivateKey(line []byte) (*ecdh.PrivateKey, error) {
	b, err := decodeKeyLine(line, privateKeyPrefix)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return ecdh.X25519().NewPrivateKey(b)
}

func readSmallFile(path string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxKeyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFileSize {
		clear(b)
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxKeyFileSize)
	}
	return b, nil
}

func readIdentity(path string, stdin io.Reader) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("--identity is required")
	}
	b, err := readSmallFile(path, stdin)
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	defer clear(b)
	k, err := parsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return k, nil
}

func generateKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// isTerminal treats any character device except the null device as a terminal;
// the standard library has no portable isatty.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(fi, null)
}
