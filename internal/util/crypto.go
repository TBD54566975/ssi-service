package util

import (
	"crypto/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Argon2SaltSize represents the recommended salt size for argon2, which is 16 bytes
	// https://tools.ietf.org/id/draft-irtf-cfrg-argon2-05.html#rfc.section.3.1
	Argon2SaltSize = 16

	// default parameters from https://pkg.go.dev/golang.org/x/crypto/argon2
	argon2Time = 1

	// From the godoc: the number of passes over the memory and the
	// memory parameter specifies the size of the memory in KiB. For example
	// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
	// adjusted to the numbers of available CPUs. The cost parameters should be
	// increased as memory latency and CPU parallelism increases
	argon2Memory = 64 * 1024
	threads      = 4
)

// XChaCha20Poly1305Encrypt takes a 32 byte key and uses XChaCha20-Poly1305 to encrypt a piece of data
func XChaCha20Poly1305Encrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.Wrap(err, "creating aead with provided key")
	}

	// generate a random nonce, leaving room for the ciphertext
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err = rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "generating nonce for encryption")
	}

	encrypted := aead.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// XChaCha20Poly1305Decrypt takes a 32 byte key and uses XChaCha20-Poly1305 to decrypt a piece of data
func XChaCha20Poly1305Decrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.Wrap(err, "creating aead with provided key")
	}

	if len(data) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short; could not decrypt data")
	}

	// split nonce and ciphertext
	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting data")
	}
	return decrypted, nil
}

// Argon2KeyGen returns an encoded string generation of a key generated using the go crypto argon2 impl
// specifically, the Argon2id version, a "hybrid version of Argon2 combining Argon2i and Argon2d."
func Argon2KeyGen(password string, salt []byte, keyLen int) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}
	if keyLen <= 0 {
		return nil, errors.New("invalid key length")
	}

	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, threads, uint32(keyLen))
	return key, nil
}

// GenerateSalt generates a random salt value for a given size
func GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("invalid size")
	}

	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}
