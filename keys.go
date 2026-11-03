package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	privateKeyPrefix = "kurumi-private-key-v1:"
	publicKeyPrefix  = "kurumi-public-key-v1:"
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

func generateKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }
