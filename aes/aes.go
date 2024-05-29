package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func Encrypt(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Add padding to the plaintext
	padding := block.BlockSize() - len(plainText)%block.BlockSize()
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	plainText = append(plainText, padText...)

	ciphertext := make([]byte, block.BlockSize()+len(plainText))
	iv := ciphertext[:block.BlockSize()]

	// Generate random initialization vector
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[block.BlockSize():], plainText)

	return ciphertext, nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	padding := ciphertext[len(ciphertext)-1]
	ciphertext = ciphertext[:len(ciphertext)-int(padding)]

	return ciphertext, nil
}

func DeriveKeyFromSHA256(inputKey []byte, size int) []byte {
	hash := sha256.Sum256(inputKey)
	return hash[:size]
}
