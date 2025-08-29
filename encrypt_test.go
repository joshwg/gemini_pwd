// encrypt_test.go
package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestEncryptDecrypt tests the encryption and decryption process.
func TestEncryptDecrypt(t *testing.T) {
	// The encryptionKey is initialized in encrypt.go's init()

	// Test case 1: Successful encryption and decryption
	originalData := []byte("this is a top secret message")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt for testing: %v", err)
	}

	encryptedData, err := encrypt(originalData, salt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedData, err := decrypt(encryptedData, salt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Errorf("Decrypted data does not match original data. Got '%s', want '%s'", decryptedData, originalData)
	}

	// Test case 2: Decryption with wrong salt
	wrongSalt := make([]byte, 16)
	if _, err := rand.Read(wrongSalt); err != nil {
		t.Fatalf("Failed to generate wrong salt for testing: %v", err)
	}

	_, err = decrypt(encryptedData, wrongSalt)
	if err == nil {
		t.Errorf("Expected a decryption error when using the wrong salt, but got nil")
	}
}

// TestDeriveKey tests the key derivation function.
func TestDeriveKey(t *testing.T) {
	salt1 := make([]byte, 16)
	rand.Read(salt1)
	key1 := deriveKey(salt1)

	// Same salt should produce the same key
	key1_repeat := deriveKey(salt1)
	if !bytes.Equal(key1, key1_repeat) {
		t.Error("deriveKey should be deterministic for the same salt")
	}

	// Different salt should produce a different key
	salt2 := make([]byte, 16)
	rand.Read(salt2)
	key2 := deriveKey(salt2)
	if bytes.Equal(key1, key2) {
		t.Error("deriveKey produced the same key for different salts")
	}
}
