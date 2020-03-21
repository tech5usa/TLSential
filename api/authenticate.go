package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrAuthFailed is for authentication failures of most types
var ErrAuthFailed = errors.New("failed to authenticate")

// ErrAuthInvalidCreds means your credentials were not parsed properly or did
// not match.
var ErrAuthInvalidCreds = errors.New("invalid credentials")

// AuthHandler parses a Basic Authentication request.
func AuthHandler(sc *ServerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		// Make sure this is of the format "Basic {credentials}"
		if len(auth) != 2 || auth[0] != "Basic" {
			// https://tools.ietf.org/html/rfc7231#section-6.5.1
			http.Error(w, ErrAuthFailed.Error(), http.StatusBadRequest)
			return
		}

		credentials, err := base64.StdEncoding.DecodeString(auth[1])
		if err != nil {
			// TODO: Provide better response.
			// https://tools.ietf.org/html/rfc7231#section-6.5.1
			http.Error(w, ErrAuthFailed.Error(), http.StatusBadRequest)
			return
		}

		// SplitN because we only want to split on the first ":" as a password
		// may contain special characters.
		pair := strings.SplitN(string(credentials), ":", 2)

		// Validate we have a username and password
		if len(pair) != 2 {
			// TODO: Provide better response.
			// https://tools.ietf.org/html/rfc7231#section-6.5.1
			http.Error(w, ErrAuthFailed.Error(), http.StatusBadRequest)
			return
		}

		name, pass := pair[0], pair[1]

		u, err := sc.us.GetUser(name)
		if err != nil || u == nil {
			// Respond with valid types of authentication.
			// https://tools.ietf.org/html/rfc7235#section-2.1
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, ErrAuthFailed.Error(), http.StatusUnauthorized)
			return
		}

		// Parse stored hash and compare
		match, err := u.ComparePasswordAndHash(pass)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Do the passwords match?
		if !match {
			// https://tools.ietf.org/html/rfc7235#section-2.1
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, ErrAuthInvalidCreds.Error(), http.StatusUnauthorized)
			return
		}

		token, err := sc.JWTSecret.Sign(u.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s", token)
	}
}
