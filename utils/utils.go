package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// HashMessage хеширует сообщение.
func hashMessage(message string) []byte {
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte(message))
	if err != nil {
		panic(err)
	}
	return msgHash.Sum(nil)
}

// SignMessage подписывает сообщение.
func SignMessage(message string, privateKey *rsa.PrivateKey) string {
	// хешируем сообщение с помощью алгоритма SHA256
	messageHashSum := hashMessage(message)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, messageHashSum, nil)
	if err != nil {
		panic(err)
	}

	return string(signature)
}

// VerifyMessage верифицирует сообщение. Вернет true если сообщение прошло верификацию.
func VerifyMessage(message string, signature string, publicKey *rsa.PublicKey) bool {
	// хешируем сообщение с помощью алгоритма SHA256
	messageHashSum := hashMessage(message)

	err := rsa.VerifyPSS(publicKey, crypto.SHA256, messageHashSum, []byte(signature), nil)
	return err == nil
}

func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return privateKey, &privateKey.PublicKey
}
