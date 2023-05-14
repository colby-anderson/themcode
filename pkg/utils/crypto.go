package utils

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func Hash(v []byte) string {
	h := sha256.Sum256(v)
	return hex.EncodeToString(h[:])
}

func GenerateSymKey() (string, cipher.AEAD, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}

	return base64.StdEncoding.EncodeToString(key), gcm, nil
}

func GenerateFromSymKey(key string) (cipher.AEAD, error) {
	key2, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(key2))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

func GenerateAsymKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func Sign(sk *rsa.PrivateKey, h string) (string, error) {
	digest := sha256.Sum256([]byte(h))
	sig, err := rsa.SignPKCS1v15(rand.Reader, sk, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func Verify(pk *rsa.PublicKey, h string, sigStr string) bool {
	sigB, err := hex.DecodeString(sigStr)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(h))
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sigB)
	return err == nil
}

//func PubEncrypt(pubkey *rsa.PublicKey, plaintext string) (string, error) {
//
//	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubkey, []byte(plaintext))
//	if err != nil {
//		return "", err
//	}
//	return base64.StdEncoding.EncodeToString(ciphertext), nil
//}

//func PubDecrypt(privkey *rsa.PrivateKey, ciphertext string) (string, error) {
//	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
//	if err != nil {
//		return "", err
//	}
//	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privkey, ciphertextBytes)
//	if err != nil {
//		return "", err
//	}
//	return string(plaintext), nil
//}

const (
	maxMsgLength = 245 // Maximum length of message that can be encrypted/decrypted with RSA-2048
)

func PubEncrypt(pubkey *rsa.PublicKey, plaintext string) (string, error) {
	ciphertextBuf := bytes.Buffer{}
	plaintextBytes := []byte(plaintext)

	// Split plaintext into sections of maxMsgLength bytes
	for i := 0; i < len(plaintextBytes); i += 245 {
		end := i + 245
		if end > len(plaintextBytes) {
			end = len(plaintextBytes)
		}
		section := plaintextBytes[i:end]

		// Encrypt section
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubkey, section)
		if err != nil {
			return "", err
		}

		_, err = ciphertextBuf.Write(ciphertext)
		if err != nil {
			return "", err
		}
	}
	return base64.StdEncoding.EncodeToString(ciphertextBuf.Bytes()), nil
}

func PubDecrypt(privkey *rsa.PrivateKey, ciphertext string) (string, error) {
	var plaintextSections []string
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	for i := 0; i < len(ciphertextBytes); i += 256 {
		end := i + 256
		if end > len(ciphertextBytes) {
			end = len(ciphertextBytes)
		}
		section := ciphertextBytes[i:end]
		// Decrypt section
		plaintextBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privkey, section)
		if err != nil {
			return "", err
		}

		plaintextSections = append(plaintextSections, string(plaintextBytes))
	}

	return strings.Join(plaintextSections, ""), nil
}

func SymEncrypt(gcm cipher.AEAD, message string) string {
	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func SymDecrypt(gcm cipher.AEAD, ciphertext string) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, cipher := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, cipher, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func EncodePublicKey(pk *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubBytes), nil
}

func DecodePublicKey(pk string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pk))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("decoded public key is not an RSA public key")
	}

	return rsaPubKey, nil
}
