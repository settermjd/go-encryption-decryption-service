package main

import (
	"bytes"
	"encoding/json"
	e "encryption-decryption-service/encryption"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/magiconair/properties/assert"
)

func getResponseBody(t *testing.T, response http.Response) []byte {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(body)
}

func marshalErrorResponse(isError bool, errorMessage string) (string, error) {
	expectedBody, err := json.Marshal(e.Response{
		Error:   isError,
		Message: errorMessage,
	})
	if err != nil {
		return "", fmt.Errorf("Could not marshal expected response body. %v", err)
	}

	return string(expectedBody), nil
}

var infoLog, errorLog *log.Logger

// setup gets called once for all defined test cases
func setup() {
	fmt.Println("Setting up test suite")
	infoLog = log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	infoLog.SetOutput(io.Discard)
	errorLog = log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)
	errorLog.SetOutput(io.Discard)
}

// teardown gets called once for all defined test cases
func teardown() {
	fmt.Println("Tearing down test suite")
}

func TestMain(m *testing.M) {
	setup()
	exitCode := m.Run()
	teardown()
	os.Exit(exitCode)
}

func TestEncryptReturnsErrorWhenTextToEncryptIsNotSetInTheRequestOrIsEmpty(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/encrypt", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.ParseForm()

	app, _ := e.NewApp(e.MakeKeyphrase(32), errorLog, infoLog)
	app.Encrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)

	expectedBody, err := marshalErrorResponse(
		true,
		`text to encrypt was not supplied in the request or was empty.`,
	)
	if err != nil {
		t.Fatal(err)
	}

	body := getResponseBody(t, *writer.Result())
	assert.Equal(t, string(body), string(expectedBody))
}

func TestCanEncryptTextInRequestBody(t *testing.T) {
	writer := httptest.NewRecorder()
	plainText := "Here is the test data.\n"

	request, err := http.NewRequest(http.MethodPost, "/encrypt", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.ParseForm()
	request.Form.Set("data", plainText)

	app, _ := e.NewApp(e.MakeKeyphrase(32), errorLog, infoLog)
	app.Encrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusOK)
	assert.Equal(t, writer.Header().Get("Content-Type"), "text/plain; charset=utf-8")

	body := getResponseBody(t, *writer.Result())
	decryptedText, err := e.DecryptData(body, app.Gcm)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plainText, string(decryptedText))
}

func TestCanDecryptText(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.ParseForm()

	app, _ := e.NewApp(e.MakeKeyphrase(32), errorLog, infoLog)

	encryptedText := e.EncryptData(
		[]byte("Here is the test data.\n"),
		app.Gcm,
		app.Nonce,
	)
	request.Form.Set("data", string(encryptedText))

	app.Decrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusOK)
	assert.Equal(t, writer.Header().Get("Content-Type"), "text/plain; charset=utf-8")

	body := getResponseBody(t, *writer.Result())
	expectedBody := "Here is the test data."
	assert.Equal(t, string(body), string(expectedBody))
}

func TestDecryptReturnsErrorWhenEncryptedTextIsNotInTheRequestOrWasEmpty(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.ParseForm()

	app, _ := e.NewApp(e.MakeKeyphrase(32), errorLog, infoLog)
	app.Decrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)
	assert.Equal(t, writer.Header().Get("Content-Type"), "application/json; charset=utf-8")

	expectedBody, err := marshalErrorResponse(
		true,
		`Encrypted text was not supplied or was empty.`,
	)
	if err != nil {
		t.Fatal(err)
	}

	defer writer.Result().Body.Close()
	body, err := io.ReadAll(writer.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.TrimSpace(body)
	assert.Equal(t, string(body), string(expectedBody))
}

func TestDecryptReturnsErrorWhenEncryptedTextCannotBeDecrypted(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	app, _ := e.NewApp(e.MakeKeyphrase(32), errorLog, infoLog)

	request.ParseForm()
	request.Form.Set("data", "Here is the test data.\n")

	app.Decrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)
	assert.Equal(t, writer.Header().Get("Content-Type"), "application/json; charset=utf-8")

	expectedBody, err := marshalErrorResponse(
		true,
		`could not decrypt data. cipher: message authentication failed`,
	)
	if err != nil {
		t.Fatal(err)
	}

	body := getResponseBody(t, *writer.Result())
	assert.Equal(t, string(body), string(expectedBody))
}

func TestDecryptReturnsMethodNotAllowedHeaderIfRequestMethodIsNotPost(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodGet, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	app := e.App{}
	app.Decrypt(writer, request)
	assert.Equal(t, writer.Result().StatusCode, http.StatusMethodNotAllowed)
}

func TestEncryptReturnsMethodNotAllowedHeaderIfRequestMethodIsNotPost(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodGet, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	app := e.App{}
	app.Encrypt(writer, request)
	assert.Equal(t, writer.Result().StatusCode, http.StatusMethodNotAllowed)
}
