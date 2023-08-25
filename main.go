package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/joho/godotenv"
)

type Response struct {
	Error   bool
	Message string
}

type App struct {
}

// EncryptFile retrieves the encryption type and the file to encrypt from the
// request and encrypts the file using that encryption type, and returns it to
// the client. Naturally, both arguments must be supplied, otherwise the
// function cannot worklied, otherwise the function cannot work.
func (a *App) EncryptFile(writer http.ResponseWriter, request *http.Request) {
	encryptionType := request.FormValue("encryption_type")
	if encryptionType == "" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(Response{
			Error:   true,
			Message: `File could not be encrypted as the encryption type is missing.`,
		})

		return
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found.")
	}

	app := App{}
	http.HandleFunc("/encrypt", app.EncryptFile)
	http.ListenAndServe(":8080", nil)
}
