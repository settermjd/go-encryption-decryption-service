package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	m "encryption-decryption-service/middleware"
	"fmt"
	"io"
	"log"
	"net/http"
)

// App is a coordinating struct for the application. It stores the app's
// keyphrase, nonce, and gsm so that they can be used throughout the
// application, as required.
type App struct {
	errorLog   *log.Logger
	Gcm        cipher.AEAD
	infoLog    *log.Logger
	key, Nonce []byte
}

// NewApp instantiates a new App struct/object with the application's keyphrase,
// nonce and gcm instance
func NewApp(keyPhrase []byte, errorLog *log.Logger, infoLog *log.Logger) (App, error) {
	app := App{
		errorLog: errorLog,
		infoLog:  infoLog,
	}
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
	app.Nonce = nonce
	app.Gcm = gcmInstance

	return app, nil
}

// Decrypt retrieves ciphered/encrypted text from the request, decrypts it, and
// returns it, if possible. If the encrypted text isn't in the request, or
// cannot be decrypted, then a JSON response is returned, indicating what went
// wrong.
func (app *App) Decrypt(writer http.ResponseWriter, request *http.Request) {
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
			Message: "Encrypted text was not supplied or was empty.",
		})

		app.errorLog.Println("Encrypted text was not supplied or was empty.")

		return
	}

	decryptedData, err := DecryptData([]byte(encryptedData), app.Gcm)
	if err != nil {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(Response{
			Error:   true,
			Message: fmt.Sprintf("%v", err),
		})

		return
	}

	app.infoLog.Printf("Successfully decrypted the encrypted text (%s)", decryptedData)

	writer.Write(decryptedData)
}

// Encrypt retrieves the encryption type and the file to encrypt from the
// request and encrypts the file using that encryption type, and returns it to
// the client. Naturally, both arguments must be supplied, otherwise the
// function cannot worklied, otherwise the function cannot work.
func (app *App) Encrypt(writer http.ResponseWriter, request *http.Request) {
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
			Message: `text to encrypt was not supplied in the request or was empty.`,
		})

		app.errorLog.Println("Text to encrypt was not supplied in the request or was empty.")

		return
	}

	encryptedText := EncryptData([]byte(plainText), app.Gcm, app.Nonce)

	app.infoLog.Printf("Successfully encrypted [\"%s\"]", plainText)

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(writer, string(encryptedText))
}

// Routes provides the application's routing table
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/encrypt", a.Encrypt)
	mux.HandleFunc("/decrypt", a.Decrypt)

	return m.LogRequest(
		m.SecureHeaders(mux),
	)
}

// Response is a small struct to return a simplistic response from the application
type Response struct {
	Error   bool
	Message string
}
