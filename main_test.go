package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/magiconair/properties/assert"
)

func marshalErrorResponse(isError bool, errorMessage string) (string, error) {
	expectedBody, err := json.Marshal(ErrorResponse{
		Error:   isError,
		Message: errorMessage,
	})
	if err != nil {
		return "", fmt.Errorf("Could not marshal expected response body. %v", err)
	}

	return string(expectedBody), nil
}

func marshalSuccessResponse(
	originalText string,
	originalTextLength int64,
	encryptedText []byte,
	encryptedTextLength int64,
) (string, error) {
	expectedBody, err := json.Marshal(SuccessResponse{
		OriginalText:        originalText,
		OriginalTextLength:  originalTextLength,
		EncryptedText:       encryptedText,
		EncryptedTextLength: encryptedTextLength,
	})
	if err != nil {
		return "", fmt.Errorf("could not marshal expected response body. %v", err)
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
	app.EncryptFile(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)

	expectedBody, err := marshalErrorResponse(
		true,
		`file could not be retrieved as none was supplied.`,
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

func TestCanEncryptUploadedFile(t *testing.T) {
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	fileText := "Here is the test file.\n"

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

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	app, _ := NewApp(key)
	app.EncryptFile(response, request)

	decryptedText, err := app.decryptFileData(app.encryptFileData([]byte(fileText)))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, response.Result().StatusCode, http.StatusOK)

	defer response.Result().Body.Close()
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.TrimSpace(body)
	var successResponse SuccessResponse
	err = json.Unmarshal(body, &successResponse)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, successResponse.OriginalText, string(decryptedText))
}
