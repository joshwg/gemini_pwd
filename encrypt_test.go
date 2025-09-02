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

// TestKeyChangeMakesDataUnreadable proves that changing PWD_SECRET_KEY
// makes all existing encrypted data permanently unreadable
func TestKeyChangeMakesDataUnreadable(t *testing.T) {
	// Original data to encrypt
	originalPassword := []byte("MySecretPassword123!")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Step 1: Encrypt with original key
	originalKey := encryptionKey // Save current key
	encryptedData, err := encrypt(originalPassword, salt)
	if err != nil {
		t.Fatalf("Failed to encrypt with original key: %v", err)
	}

	// Step 2: Verify we can decrypt with the same key
	decryptedData, err := decrypt(encryptedData, salt)
	if err != nil {
		t.Fatalf("Failed to decrypt with original key: %v", err)
	}
	if !bytes.Equal(originalPassword, decryptedData) {
		t.Fatalf("Decrypted data doesn't match original. Expected: %s, Got: %s",
			string(originalPassword), string(decryptedData))
	}
	t.Logf("✅ Successfully encrypted and decrypted with original key")

	// Step 3: Simulate changing the PWD_SECRET_KEY by changing encryptionKey
	newKey := []byte("DifferentKey32BytesLongForTest!!")
	if len(newKey) != 32 {
		t.Fatalf("New key must be 32 bytes, got %d", len(newKey))
	}
	encryptionKey = newKey // Change the global encryption key

	// Step 4: Try to decrypt the same data with the new key
	_, err = decrypt(encryptedData, salt)
	if err == nil {
		t.Fatalf("ERROR: Decryption should have failed with changed key, but it succeeded!")
	}
	t.Logf("✅ Decryption correctly failed with new key: %v", err)

	// Step 5: Prove the new key works for new data
	newPassword := []byte("NewPasswordWithNewKey456!")
	newEncryptedData, err := encrypt(newPassword, salt)
	if err != nil {
		t.Fatalf("Failed to encrypt with new key: %v", err)
	}

	newDecryptedData, err := decrypt(newEncryptedData, salt)
	if err != nil {
		t.Fatalf("Failed to decrypt with new key: %v", err)
	}
	if !bytes.Equal(newPassword, newDecryptedData) {
		t.Fatalf("New key encryption/decryption failed")
	}
	t.Logf("✅ New key works fine for new data")

	// Step 6: Restore original key and verify old data is accessible again
	encryptionKey = originalKey
	restoredData, err := decrypt(encryptedData, salt)
	if err != nil {
		t.Fatalf("Failed to decrypt with restored original key: %v", err)
	}
	if !bytes.Equal(originalPassword, restoredData) {
		t.Fatalf("Restored decryption failed")
	}
	t.Logf("✅ Original key restored - old data is accessible again")

	// Step 7: Verify new key data is now unreadable with original key
	_, err = decrypt(newEncryptedData, salt)
	if err == nil {
		t.Fatalf("ERROR: Should not be able to decrypt new-key data with original key")
	}
	t.Logf("✅ Data encrypted with new key is unreadable with original key: %v", err)

	t.Log("\n🔑 PROOF COMPLETE:")
	t.Log("   • Changing PWD_SECRET_KEY makes existing encrypted data permanently unreadable")
	t.Log("   • Each key can only decrypt data that was encrypted with that same key")
	t.Log("   • Data encrypted with Key A cannot be decrypted with Key B")
	t.Log("   • Restoring the original key makes the original data readable again")
}

// TestRealWorldKeyChangeScenario simulates what happens in a real password manager
// when the PWD_SECRET_KEY is changed after passwords are already stored
func TestRealWorldKeyChangeScenario(t *testing.T) {
	t.Log("🔐 SIMULATING REAL-WORLD KEY CHANGE SCENARIO")

	// Simulate existing passwords in the system
	passwords := []struct {
		site     string
		username string
		password string
		notes    string
	}{
		{"gmail.com", "user@example.com", "SuperSecret123!", "Work email account"},
		{"github.com", "developer", "GitPassword456!", "Development account"},
		{"bank.com", "customer123", "BankPass789!", "Banking login"},
	}

	// Step 1: Store passwords with original key
	originalKey := encryptionKey
	var storedPasswords []struct {
		site, username                          string
		encryptedPassword, encryptedNotes, salt []byte
	}

	t.Log("📥 Storing passwords with original key...")
	for _, pwd := range passwords {
		salt := make([]byte, 16)
		rand.Read(salt)

		encryptedPassword, err := encrypt([]byte(pwd.password), salt)
		if err != nil {
			t.Fatalf("Failed to encrypt password for %s: %v", pwd.site, err)
		}

		encryptedNotes, err := encrypt([]byte(pwd.notes), salt)
		if err != nil {
			t.Fatalf("Failed to encrypt notes for %s: %v", pwd.site, err)
		}

		storedPasswords = append(storedPasswords, struct {
			site, username                          string
			encryptedPassword, encryptedNotes, salt []byte
		}{
			site:              pwd.site,
			username:          pwd.username,
			encryptedPassword: encryptedPassword,
			encryptedNotes:    encryptedNotes,
			salt:              salt,
		})
		t.Logf("   ✅ Stored password for %s", pwd.site)
	}

	// Step 2: Verify all passwords can be decrypted with original key
	t.Log("🔍 Verifying all passwords can be decrypted with original key...")
	for i, stored := range storedPasswords {
		decryptedPassword, err := decrypt(stored.encryptedPassword, stored.salt)
		if err != nil {
			t.Fatalf("Failed to decrypt password for %s: %v", stored.site, err)
		}
		if string(decryptedPassword) != passwords[i].password {
			t.Fatalf("Password mismatch for %s", stored.site)
		}
		t.Logf("   ✅ Successfully decrypted password for %s", stored.site)
	}

	// Step 3: CHANGE THE KEY (simulate production key change)
	t.Log("🔄 CHANGING ENCRYPTION KEY (simulating production key rotation)...")
	newProductionKey := []byte("NewProductionKey123456789012345!")
	if len(newProductionKey) != 32 {
		t.Fatalf("New production key must be 32 bytes")
	}
	encryptionKey = newProductionKey
	t.Log("   ⚠️  PWD_SECRET_KEY has been changed!")

	// Step 4: Try to access existing passwords - SHOULD FAIL
	t.Log("💥 Attempting to access existing passwords with new key...")
	failureCount := 0
	for _, stored := range storedPasswords {
		_, err := decrypt(stored.encryptedPassword, stored.salt)
		if err != nil {
			failureCount++
			t.Logf("   ❌ CANNOT decrypt password for %s: %v", stored.site, err)
		} else {
			t.Fatalf("ERROR: Should not be able to decrypt %s with new key!", stored.site)
		}
	}

	if failureCount != len(storedPasswords) {
		t.Fatalf("Expected all %d passwords to be unreadable, but %d succeeded",
			len(storedPasswords), len(storedPasswords)-failureCount)
	}
	t.Logf("   ✅ CONFIRMED: All %d stored passwords are now unreadable", failureCount)

	// Step 5: Demonstrate that new passwords work fine with new key
	t.Log("🆕 Testing new password storage with new key...")
	newPassword := "NewPasswordWithNewKey999!"
	newSalt := make([]byte, 16)
	rand.Read(newSalt)

	newEncrypted, err := encrypt([]byte(newPassword), newSalt)
	if err != nil {
		t.Fatalf("Failed to encrypt with new key: %v", err)
	}

	newDecrypted, err := decrypt(newEncrypted, newSalt)
	if err != nil {
		t.Fatalf("Failed to decrypt with new key: %v", err)
	}

	if string(newDecrypted) != newPassword {
		t.Fatalf("New key encryption/decryption failed")
	}
	t.Log("   ✅ New password storage works perfectly with new key")

	// Step 6: Demonstrate recovery by restoring original key
	t.Log("🔄 RECOVERY: Restoring original key...")
	encryptionKey = originalKey
	t.Log("   ✅ Original key restored")

	// Step 7: Verify old passwords are accessible again
	t.Log("🔍 Verifying old passwords are accessible again...")
	for i, stored := range storedPasswords {
		decryptedPassword, err := decrypt(stored.encryptedPassword, stored.salt)
		if err != nil {
			t.Fatalf("Failed to decrypt password for %s after key restoration: %v", stored.site, err)
		}
		if string(decryptedPassword) != passwords[i].password {
			t.Fatalf("Password mismatch for %s after restoration", stored.site)
		}
		t.Logf("   ✅ Successfully recovered password for %s", stored.site)
	}

	// Final summary
	t.Log("\n🎯 REAL-WORLD SCENARIO CONCLUSIONS:")
	t.Log("   1. ❌ Changing PWD_SECRET_KEY makes ALL existing passwords unreadable")
	t.Log("   2. ❌ Users would lose access to all their saved passwords")
	t.Log("   3. ❌ The encrypted data remains in the database but becomes useless")
	t.Log("   4. ✅ New passwords can be saved with the new key")
	t.Log("   5. ✅ Restoring the original key recovers all old passwords")
	t.Log("   6. ⚠️  In production: EXPORT BEFORE changing keys, then RE-IMPORT!")
}
