package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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
	expectedBody, err := json.Marshal(Response{
		Error:   isError,
		Message: errorMessage,
	})
	if err != nil {
		return "", fmt.Errorf("Could not marshal expected response body. %v", err)
	}

	return string(expectedBody), nil
}

func TestEncryptFileMustReceiveFileToEncrypt(t *testing.T) {
	// Initialize a new httptest.ResponseRecorder.
	writer := httptest.NewRecorder()

	// Initialize a new dummy http.Request.
	request, err := http.NewRequest(http.MethodPost, "/encrypt", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.ParseMultipartForm(32 << 20)

	app := App{}
	app.Encrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)

	expectedBody, err := marshalErrorResponse(
		true,
		`file could not be retrieved as none was supplied.`,
	)
	if err != nil {
		t.Fatal(err)
	}

	body := getResponseBody(t, *writer.Result())
	assert.Equal(t, string(body), string(expectedBody))
}

func TestCanEncryptUploadedFile(t *testing.T) {
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	fileText := "Here is the test data.\n"

	go func() {
		defer writer.Close()
		// We create the form data field 'fileupload'
		// which returns another writer to write the actual file
		part, err := writer.CreateFormFile("upload_file", "test-file.txt")
		if err != nil {
			t.Error(err)
		}
		fmt.Fprint(part, fileText)
	}()

	response := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/encrypt", pr)
	if err != nil {
		t.Fatal(err)
	}
	request.ParseMultipartForm(32 << 20)
	request.Header.Add("Content-Type", writer.FormDataContentType())

	keyphrase := MakeKeyphrase(32)
	app, _ := NewApp(keyphrase)
	app.Encrypt(response, request)

	assert.Equal(t, response.Result().StatusCode, http.StatusOK)

	body := getResponseBody(t, *response.Result())
	var result EncryptedResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		t.Fatal(err)
	}

	decryptedText, err := app.decryptData(result.Text)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, fileText, string(decryptedText))
}

func TestCanDecryptText(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.ParseForm()

	keyphrase := MakeKeyphrase(32)
	app, _ := NewApp(keyphrase)

	encryptedText := app.encryptData([]byte("Here is the test data.\n"))
	request.Form.Set("data", string(encryptedText))

	app.Decrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusOK)
	assert.Equal(t, writer.Header().Get("Content-Type"), "text/plain; charset=utf-8")

	body := getResponseBody(t, *writer.Result())
	expectedBody := "Here is the test data."
	assert.Equal(t, string(body), string(expectedBody))
}

func TestDecryptReturnsErrorWhenEncryptedTextIsNotInTheRequest(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodPost, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.ParseForm()

	app := App{}
	app.Decrypt(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)
	assert.Equal(t, writer.Header().Get("Content-Type"), "application/json; charset=utf-8")

	expectedBody, err := marshalErrorResponse(
		true,
		`Encrypted text was not supplied.`,
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

	keyphrase := MakeKeyphrase(32)
	app, _ := NewApp(keyphrase)

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

	app := App{}
	app.Decrypt(writer, request)
	assert.Equal(t, writer.Result().StatusCode, http.StatusMethodNotAllowed)
}

func TestEncryptReturnsMethodNotAllowedHeaderIfRequestMethodIsNotPost(t *testing.T) {
	writer := httptest.NewRecorder()

	request, err := http.NewRequest(http.MethodGet, "/decrypt", nil)
	if err != nil {
		t.Fatal(err)
	}

	app := App{}
	app.Encrypt(writer, request)
	assert.Equal(t, writer.Result().StatusCode, http.StatusMethodNotAllowed)
}
