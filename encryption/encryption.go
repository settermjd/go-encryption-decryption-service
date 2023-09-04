package encryption

import "crypto/rand"

func MakeKeyphrase(size int) []byte {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}

	return bytes
}
