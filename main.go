package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
)

func EncryptMessage(key []byte, message string) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func main() {
	var passkey string
	var secret string
	var message string
	var salt string

	flag.StringVar(&secret, "secret", "", "secret")
	flag.StringVar(&secret, "s", "", "secret")
	flag.StringVar(&message, "message", "", "message")
	flag.StringVar(&message, "m", "", "message")
	flag.StringVar(&passkey, "p", "", "passkey")
	flag.StringVar(&passkey, "passkey", "", "passkey")
	flag.StringVar(&salt, "salt", "c18148a1d65dfc2d4b1fa3d677284dge", "salt")

	flag.Parse()

	if passkey == "" {
		log.Fatal("Passkey is empty, please setup Passkey")
	}

	//Получаем ключ от пароля по алгоритму pbkdf2, используя SHA3 512
	dk := []byte(passkey)
	var steps int
	for _, b := range dk {
		steps += int(b)
	}
	for i := 0; i < (steps % 64); i++ {
		dk = pbkdf2.Key(dk, []byte(salt), 4096, 32, sha3.New512)
	}
	if secret != "" {
		encryptMsg := secret
		for i := 0; i < (steps % 8); i++ {
			encryptMsg, _ = EncryptMessage(dk, encryptMsg)
		}
		fmt.Println(encryptMsg)
	}
	if message != "" {
		dencryptMsg := message
		for i := 0; i < (steps % 8); i++ {
			dencryptMsg, _ = DecryptMessage(dk, dencryptMsg)
		}
		fmt.Println(dencryptMsg)
	}
}
