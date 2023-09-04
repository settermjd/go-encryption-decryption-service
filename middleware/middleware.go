package middleware

import (
	"log"
	"net/http"
)

// SecureHeaders adds the minimum required headers to a request
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self';")
		writer.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "deny")
		writer.Header().Set("X-XSS-Protection", "0")
		next.ServeHTTP(writer, request)
	})
}

// LogRequest logs the route being requested
func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("Request made to %s route.", request.RequestURI)
		next.ServeHTTP(writer, request)
	})
}
