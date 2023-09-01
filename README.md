# Go Encryption and Decryption API
![Build and Test workflow](https://github.com/settermjd/go-encryption-decryption-service/actions/workflows/go.yml/badge.svg)

This is a small Go API which encrypts and decrypts a text string.

## Prerequisites

You don't need much to use the code, just the following:

- A recent version of [Go](https://go.dev/dl/)
- A tool to make requests, such as [curl](https://curl.se) or [Postman](https://www.postman.com/downloads/)

## Usage

Once you clone the code locally, to wherever you keep your Go code, start it by running the command below.

```bash
go run main.go
```

### Encrypt a string

To encrypt a string, make a POST request to http://localhost:4000/encrypt, and in the body of the request, include a parameter named `data` containing the string that you want to encrypt.

### Decrypt a string

To decrypt a string, make a POST request to http://localhost:4000/decrypt, and in the body of the request, include a parameter named `data` containing the string that you want to decrypt.