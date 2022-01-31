package sqlprotector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// The entry key is the password value to use for AES encrypting and decrypting of the values to/from the database.
var sqlProtectorPassphrase []byte

func init() {
	SetSQLProtectorPassphrase([]byte(os.Getenv("DARE_PASSPHRASE")))
}

// GetSQLProtectorPassphrase returns the password used for encryption.
func GetSQLProtectorPassphrase() []byte {
	return sqlProtectorPassphrase
}

// SetSQLProtectorPassphrase sets the password to use for encryption.
func SetSQLProtectorPassphrase(passphrase []byte) error {
	passphraseLen := len(passphrase)

	// DEVELOPERS NOTE:
	// Why are we limited to 16, 24, and or 32? The `aes.NewCipher` function only
	// allows those sizes as per documentation via https://pkg.go.dev/crypto/aes#NewCipher.
	// Since we are using `aes.NewCipher` in the `encrypt` function, we must
	// enforce this passphrase length here.
	if passphraseLen != 16 && passphraseLen != 24 && passphraseLen != 32 {
		return fmt.Errorf("Passphrase must be 16, 24, or 32 bytes and not %d", passphraseLen)
	}
	sqlProtectorPassphrase = passphrase
	return nil
}

func encrypt(plaintext string) (chipertext string, err error) {
	block, _ := aes.NewCipher(sqlProtectorPassphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	ciphertextByte := gcm.Seal(
		nonce,
		nonce,
		[]byte(plaintext),
		nil)
	chipertext = base64.StdEncoding.EncodeToString(ciphertextByte)
	return
}

func decrypt(cipherText string) (plainText string, err error) {
	block, err := aes.NewCipher(sqlProtectorPassphrase)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()

	ciphertextByte, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return
	}
	nonce, ciphertextByteClean := ciphertextByte[:nonceSize], ciphertextByte[nonceSize:]
	plaintextByte, err := gcm.Open(
		nil,
		nonce,
		ciphertextByteClean,
		nil)
	if err != nil {
		return
	}
	plainText = string(plaintextByte)

	return
}
