package main

import (
	"bytes"
	"crypto/rsa"
	"diana-e-signature/utils"
	"encoding/gob"
	"io"
	"log"
	"net/http"
)

func main() {
	log.Println("Запрашиваем публичный ключ сервера")
	var serverPublicKey rsa.PublicKey
	getPublicKeyStatus, getPublicKeyStatusCode := sendRequestToServer("GET", "public-key", &serverPublicKey)
	if getPublicKeyStatusCode != http.StatusOK {
		log.Fatal("returned status:", getPublicKeyStatus, getPublicKeyStatusCode)
	}

	log.Println("Запрашиваем генерацию случайного сообщения на сервере")
	var randomSignedMessageResponse struct {
		Message   string
		Signature string
	}
	getRandomSignedMessageStatus, getRandomSignedMessageStatusCode := sendRequestToServer("GET", "signed-message", &randomSignedMessageResponse)
	if getRandomSignedMessageStatusCode != http.StatusOK {
		log.Fatal("returned status:", getRandomSignedMessageStatus, getRandomSignedMessageStatusCode)
	}

	log.Println("Верификация подписанного сервером сообщения:", utils.VerifyMessage(randomSignedMessageResponse.Message, randomSignedMessageResponse.Signature, &serverPublicKey))
}

// sendRequestToServer отправляет запрос на сервер. Возвращает статус-строку, код статуса
func sendRequestToServer[T any](method, path string, responseDest *T) (string, int) {
	req, err := http.NewRequest(method, "http://localhost:5245/"+path, nil)
	if err != nil {
		log.Fatal("can't create request:", err.Error())
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("can't login:", err.Error())
	}

	if response.StatusCode != http.StatusOK {
		return response.Status, response.StatusCode
	}

	responseBodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal("can't read response body:", err.Error())
	}

	var responseBody T
	decoder := gob.NewDecoder(bytes.NewReader(responseBodyBytes))
	if err := decoder.Decode(&responseBody); err != nil {
		log.Fatal("can't decode response body:", err.Error())
	}

	*responseDest = responseBody

	return response.Status, response.StatusCode
}
