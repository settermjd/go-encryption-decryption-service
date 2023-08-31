package main

import (
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

type Response struct {
	Error   bool
	Message string
}

type EncryptedResponse struct {
	Text []byte
}

func MakeKeyphrase(size int) []byte {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}

	return bytes
}

// App is a coordinating struct for the application. It stores the app's
// keyphrase, nonce, and gsm so that they can be used throughout the
// application, as required.
type App struct {
	key, nonce []byte
	gcm        cipher.AEAD
}

// NewApp instantiates a new App struct/object with the application's keyphrase,
// nonce and gcm instance
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

// encryptData encrypts/ciphers the text and returns it.
func (a App) encryptData(plainText []byte) []byte {
	return a.gcm.Seal(a.nonce, a.nonce, plainText, nil)
}

// decryptData decrypts/deciphers the data in cipheredText and returns it,
// or the error that occurred while doing so.
func (a App) decryptData(cipheredText []byte) ([]byte, error) {
	nonce := cipheredText[:a.gcm.NonceSize()]
	cipheredText = cipheredText[a.gcm.NonceSize():]
	originalText, err := a.gcm.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data. %v", err)
	}
	return originalText, nil
}

// Decrypt retrieves ciphered/encrypted text from the request, decrypts it, and
// returns it, if possible. If the encrypted text isn't in the request, or
// cannot be decrypted, then a JSON response is returned, indicating what went
// wrong.
func (a *App) Decrypt(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		writer.Header().Set("Allow", "POST")
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	encryptedData := request.FormValue("data")
	if encryptedData == "" {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(Response{
			Error:   true,
			Message: "Encrypted text was not supplied.",
		})

		return
	}

	decryptedData, err := a.decryptData([]byte(encryptedData))
	if err != nil {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(Response{
			Error:   true,
			Message: fmt.Sprintf("%v", err),
		})

		return
	}
	writer.Write(decryptedData)
}

// Encrypt retrieves the encryption type and the file to encrypt from the
// request and encrypts the file using that encryption type, and returns it to
// the client. Naturally, both arguments must be supplied, otherwise the
// function cannot worklied, otherwise the function cannot work.
func (a *App) Encrypt(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		writer.Header().Set("Allow", "POST")
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	plainText := request.FormValue("data")
	if plainText == "" {
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(Response{
			Error:   true,
			Message: `text to encrypt was not supplied in the request.`,
		})

		return
	}

	encryptedText := a.encryptData([]byte(plainText))

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(writer, string(encryptedText))
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found.")
	}

	// Generate a random 32 byte key for AES-256
	keyphrase := MakeKeyphrase(32)
	app, err := NewApp(keyphrase)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/encrypt", app.Encrypt)
	mux.HandleFunc("/decrypt", app.Decrypt)

	log.Print("Starting server on :4000")
	err = http.ListenAndServe(":4000", mux)
	log.Fatal(err)
}
