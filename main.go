package main

import (
	enc "encryption-decryption-service/encryption"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found.")
	}

	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	// Generate a random 32 byte key for AES-256
	keyphrase := enc.MakeKeyphrase(32)
	app, err := enc.NewApp(keyphrase, errorLog, infoLog)
	if err != nil {
		errorLog.Fatal(err)
	}

	addr := flag.String("addr", ":4000", "HTTP network address")
	srv := &http.Server{
		Addr:     *addr,
		ErrorLog: errorLog,
		Handler:  app.Routes(),
	}

	infoLog.Printf("Starting server on %s", *addr)
	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}
