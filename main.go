package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/joho/godotenv"
)

type ErrorResponse struct {
	Error   bool
	Message string
}

type SuccessResponse struct {
	OriginalText                            string
	OriginalTextLength, EncryptedTextLength int64
	EncryptedText                           []byte
}

type App struct {
	key, nonce []byte
	gcm        cipher.AEAD
}

func NewApp(keyPhrase []byte) (App, error) {
	app := App{}
	aesBlock, err := aes.NewCipher(keyPhrase)
	if err != nil {
		return app, fmt.Errorf("could not generate cipher. %v", err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return app, fmt.Errorf("could not generate a new GCM. %v", err)
	}

	nonce := make([]byte, gcmInstance.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return app, fmt.Errorf("could not generate a nonce. %v", err)
	}

	app.key = keyPhrase
	app.nonce = nonce
	app.gcm = gcmInstance

	return app, nil
}

// encryptFileData encrypts text and returns it.
func (a App) encryptFileData(plainText []byte) []byte {
	return a.gcm.Seal(nil, a.nonce, plainText, nil)
}

func (a App) decryptFileData(cipheredText []byte) ([]byte, error) {
	originalText, err := a.gcm.Open(nil, a.nonce, cipheredText, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data. %v", err)
	}
	return originalText, nil
}

// EncryptFile retrieves the encryption type and the file to encrypt from the
// request and encrypts the file using that encryption type, and returns it to
// the client. Naturally, both arguments must be supplied, otherwise the
// function cannot worklied, otherwise the function cannot work.
func (a *App) EncryptFile(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	file, fileHeader, err := request.FormFile("upload_file")
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(ErrorResponse{
			Error:   true,
			Message: `file could not be retrieved as none was supplied.`,
		})

		return
	}
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(ErrorResponse{
			Error:   true,
			Message: fmt.Sprintf("could not upload file. %v", err),
		})

		return
	}

	encryptedText := a.gcm.Seal(a.nonce, a.nonce, buf.Bytes(), nil)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(ErrorResponse{
			Error:   true,
			Message: fmt.Sprintf("could not encrypt file. %v", err),
		})

		return
	}

	writer.WriteHeader(http.StatusOK)
	json.NewEncoder(writer).Encode(SuccessResponse{
		OriginalText:        buf.String(),
		OriginalTextLength:  fileHeader.Size,
		EncryptedText:       encryptedText,
		EncryptedTextLength: int64(len(encryptedText)),
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found.")
	}

	// Generate a random 32 byte key for AES-256
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}

	app, err := NewApp(bytes)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/encrypt", app.EncryptFile)

	log.Print("Starting server on :4000")
	err = http.ListenAndServe(":4000", mux)
	log.Fatal(err)
}
