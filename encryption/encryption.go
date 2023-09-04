package encryption

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func MakeKeyphrase(size int) []byte {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}

	return bytes
}

// EncryptData encrypts/ciphers the text and returns it.
func EncryptData(plainText []byte, gcm cipher.AEAD, nonce []byte) []byte {
	return gcm.Seal(nonce, nonce, plainText, nil)
}

// DecryptData decrypts/deciphers the data in cipheredText and returns it,
// or the error that occurred while doing so.
func DecryptData(cipheredText []byte, gcm cipher.AEAD) ([]byte, error) {
	nonce := cipheredText[:gcm.NonceSize()]
	cipheredText = cipheredText[gcm.NonceSize():]
	originalText, err := gcm.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data. %v", err)
	}
	return originalText, nil
}
