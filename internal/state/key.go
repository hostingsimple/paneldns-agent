package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// File names inside the state directory.
const (
	KeyFile      = "agent.key"
	NextKeyFile  = "agent.key.next" // written before /rotate, renamed after
	IdentityFile = "identity.json"
	SequenceFile = "sequence.json"
	StateFile    = "state.json"
	LockFile     = ".lock"
)

// GenerateKey creates an Ed25519 key pair from r (crypto/rand when nil).
func GenerateKey(r io.Reader) (ed25519.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	_, priv, err := ed25519.GenerateKey(r)
	return priv, err
}

// EncodeKey returns the private key as a PKCS #8 PEM block, the format
// `openssl pkey -in agent.key -pubout` reads.
func EncodeKey(k ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// WriteKey stores the private key with mode 0600.
func WriteKey(path string, k ed25519.PrivateKey) error {
	b, err := EncodeKey(k)
	if err != nil {
		return err
	}
	return WriteAtomic(path, b, 0o600)
}

// ErrKeyMode is returned when the key file is readable by others.
var ErrKeyMode = errors.New("key file must have mode 0600")

// LoadKey reads the private key and refuses a file readable by group or
// others.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o: %w", path, fi.Mode().Perm(), ErrKeyMode)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeKey(b)
}

// DecodeKey parses a PKCS #8 PEM Ed25519 private key.
func DecodeKey(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("key file is not a PEM PRIVATE KEY")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key file does not hold an Ed25519 key")
	}
	return ek, nil
}
