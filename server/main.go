package main

import (
	"bytes"
	"crypto/rsa"
	"diana-e-signature/utils"
	"encoding/gob"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberLogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/pkg/errors"
)

const ServerPort = 5245

func main() {
	server := NewServer()

	if startAppErr := server.Listen(fmt.Sprintf(":%d", ServerPort)); startAppErr != nil {
		log.Fatalln("can't start fiber app", "err", startAppErr.Error())
	}
}

type Server struct {
	app                 *fiber.App
	clientPublicKeysMap map[string]rsa.PublicKey

	serverPrivateKey *rsa.PrivateKey
	serverPublicKey  *rsa.PublicKey
}

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}

func (s *Server) getClientID(c *fiber.Ctx) (string, error) {
	log.Println("GetReqHeaders", c.GetReqHeaders())
	clientID, ok := c.GetReqHeaders()["Es-Client-Id"]
	if !ok {
		return "", errors.New("es-client-id must be passed in")
	}

	return clientID[0], nil
}

func (s *Server) login(c *fiber.Ctx) error {
	clientID, err := s.getClientID(c)
	if err != nil {
		return err
	}

	var publicKey rsa.PublicKey
	decoder := gob.NewDecoder(bytes.NewReader(c.Body()))
	if err := decoder.Decode(&publicKey); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Failed to decode data")
	}

	s.clientPublicKeysMap[clientID] = publicKey

	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) verifyMessage(c *fiber.Ctx) error {
	clientID, err := s.getClientID(c)
	if err != nil {
		return err
	}

	publicKey, ok := s.clientPublicKeysMap[clientID]
	if !ok {
		return c.Status(fiber.StatusBadRequest).SendString("client hasn't logged in")
	}

	body := struct {
		Message   string
		Signature string
	}{}

	decoder := gob.NewDecoder(bytes.NewReader(c.Body()))
	if err := decoder.Decode(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Failed to decode data")
	}

	if utils.VerifyMessage(body.Message, body.Signature, &publicKey) {
		return c.Status(fiber.StatusOK).SendString("success")
	} else {
		return c.Status(fiber.StatusUnauthorized).SendString("failure")
	}
}

func (s *Server) getPublicKey(c *fiber.Ctx) error {
	buffer := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buffer)
	if err := encoder.Encode(*s.serverPublicKey); err != nil {
		return errors.Wrap(err, "can't encode public key for send")
	}

	return c.Status(fiber.StatusOK).Send(buffer.Bytes())
}

func (s *Server) getRandomSignedMessage(c *fiber.Ctx) error {
	message := fmt.Sprintf("random message from server %d", time.Now().Unix())
	signature := utils.SignMessage(message, s.serverPrivateKey)

	randomSignedMessageResponse := struct {
		Message   string
		Signature string
	}{
		Message:   message,
		Signature: signature,
	}

	buffer := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buffer)
	if err := encoder.Encode(randomSignedMessageResponse); err != nil {
		return errors.Wrap(err, "can't encode random message for send")
	}

	return c.Status(fiber.StatusOK).Send(buffer.Bytes())
}

func NewServer() *Server {
	app := fiber.New()
	app.Use(fiberLogger.New())
	privateKey, publicKey := utils.GenerateKeyPair()

	newServer := &Server{
		app:                 app,
		clientPublicKeysMap: make(map[string]rsa.PublicKey),
		serverPrivateKey:    privateKey,
		serverPublicKey:     publicKey,
	}

	// регистрация клиента (отправка публичного ключа серверу)
	app.Post("/login", newServer.login)
	// верификация подписанного клиентом сообщения (на основе публичного ключа клиента)
	app.Post("/verify-message", newServer.verifyMessage)

	// получение публичного ключа сервера
	app.Get("/public-key", newServer.getPublicKey)
	// получение случайного сообщения, подписанного сервером
	app.Get("/signed-message", newServer.getRandomSignedMessage)

	return newServer
}
