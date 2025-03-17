package main

import (
	"bytes"
	"diana-e-signature/utils"
	"encoding/gob"
	"log"
	"net/http"
)

func main() {
	log.Println("Генерируем пару ключей")
	privateKey, publicKey := utils.GenerateKeyPair()

	log.Println("Регистрируемся на сервере (отправляем публичный ключ)")
	loginStatus, loginStatusCode := sendRequestToServer("POST", "login", publicKey)
	if loginStatusCode != http.StatusOK {
		log.Fatal("returned status:", loginStatus, loginStatusCode)
	}

	message := "Hello from client (scenario 1)"

	log.Println("Подписываем сообщение")
	signature := utils.SignMessage(message, privateKey)

	log.Println("Передаем сообщение и проверяем статус верификации")
	verifyStatus, verifyStatusCode := sendRequestToServer("POST", "verify-message", struct {
		Message   string
		Signature string
	}{
		Message:   message,
		Signature: signature,
	})
	log.Println("Статус верификации:", verifyStatus, verifyStatusCode)
}

// sendRequestToServer отправляет запрос на сервер. Возвращает статус-строку, код статуса
func sendRequestToServer[T any](method, path string, reqBody T) (string, int) {
	buffer := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buffer)
	if err := encoder.Encode(reqBody); err != nil {
		log.Fatal("can't encode public key for send:", err.Error())
	}

	req, err := http.NewRequest(method, "http://localhost:5245/"+path, buffer)
	if err != nil {
		log.Fatal("can't create request:", err.Error())
	}
	req.Header.Add("es-client-id", "client-scenario-1")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("can't login:", err.Error())
	}

	return response.Status, response.StatusCode
}
