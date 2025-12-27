// Copyright (C) 2025 Joshua Goldstein

// encrypt.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"gemini_pwd/pkg/logger"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

var encryptionKey []byte

func init() {

	keyStr := os.Getenv("PWD_SECRET_KEY")
	if keyStr == "" {
		logger.Fatal("PWD_SECRET_KEY environment variable is not set. Refusing to start. You must provide a secure 32-byte key.", fmt.Errorf("missing key"))
	}

	// AES-256 requires a 32-byte key. Refuse to start if the key is not the correct size.
	if len(keyStr) != 32 {
		logger.Fatal("Invalid PWD_SECRET_KEY length: must be exactly 32 bytes, but got %d bytes. Refusing to start.", fmt.Errorf("wrong key length"), len(keyStr))
	}

	encryptionKey = []byte(keyStr)
	logger.Success("Encryption system initialized with %d-byte key", len(encryptionKey))
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
