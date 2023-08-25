package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/magiconair/properties/assert"
)

func marshalResponse(isError bool, errorMessage string) (string, error) {
	expectedBody, err := json.Marshal(Response{
		Error:   isError,
		Message: errorMessage,
	})
	if err != nil {
		return "", fmt.Errorf("Could not marshal expected response body. %v", err)
	}

	return string(expectedBody), nil
}

func TestEncryptFileMustReceiveEncryptionType(t *testing.T) {
	// Initialize a new httptest.ResponseRecorder.
	writer := httptest.NewRecorder()

	// Initialize a new dummy http.Request.
	request, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	app := App{}
	app.EncryptFile(writer, request)

	assert.Equal(t, writer.Result().StatusCode, http.StatusBadRequest)

	expectedBody, err := marshalResponse(true, `File could not be encrypted as the encryption type is missing.`)
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
