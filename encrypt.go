// encrypt.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

var encryptionKey []byte

func init() {
	keyStr := os.Getenv("PWD_SECRET_KEY")
	if keyStr == "" {
		keyStr = "ThisIsASecretKeyYouShouldReplace"
	}
	// AES-256 requires a 32-byte key. We'll panic on startup if the key is not the correct size.
	if len(keyStr) != 32 {
		panic(fmt.Sprintf("Invalid PWD_SECRET_KEY length: must be 32 bytes, but got %d", len(keyStr)))
	}
	encryptionKey = []byte(keyStr)
}

// deriveKey uses PBKDF2 to create a unique key for an entry from the master key and a salt.
func deriveKey(salt []byte) []byte {
	// The parameters (4096 iterations, 32-byte key length, SHA-256) are standard.
	return pbkdf2.Key(encryptionKey, salt, 4096, 32, sha256.New)
}

// encrypt encrypts data using a key derived from the master key and the provided salt.
func encrypt(data, salt []byte) ([]byte, error) {
	derivedKey := deriveKey(salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using a key derived from the master key and the provided salt.
func decrypt(data, salt []byte) ([]byte, error) {
	derivedKey := deriveKey(salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
