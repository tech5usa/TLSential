package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/config"
	"github.com/ImageWare/TLSential/user"
)

// ErrAuthFailed is for authentication failures of most types
var ErrAuthFailed = errors.New("failed to authenticate")

// ErrAuthInvalidCreds means your credentials were not parsed properly or did
// not match.
var ErrAuthInvalidCreds = errors.New("invalid credentials")

// AuthHandler provides an interface for all calls to the api/authenticate
// endpoints.
type AuthHandler interface {
	Authenticate() http.HandlerFunc
}

type authHandler struct {
	cs config.Service
	us user.Service
}

// NewAuthHandler returns a instantiated AuthHandler for use in a router.
func NewAuthHandler(cs config.Service, us user.Service) AuthHandler {
	return &authHandler{cs, us}
}

// AuthHandler parses a Basic Authentication request.
func (h *authHandler) Authenticate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		username, password, ok := r.BasicAuth()

		// Make sure this is of the format "Basic {credentials}"
		if !ok {
			// https://tools.ietf.org/html/rfc7231#section-6.5.1
			log.Printf("Authenticate, parsing credentials not ok")
			http.Error(w, ErrAuthFailed.Error(), http.StatusBadRequest)
			return
		}

		u, err := h.us.GetUser(username)
		if err != nil || u == nil {
			// Respond with valid types of authentication.
			// https://tools.ietf.org/html/rfc7235#section-2.1
			log.Printf("Authenticate, GetUser(), %v", err)
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, ErrAuthFailed.Error(), http.StatusUnauthorized)
			return
		}

		// Parse stored hash and compare
		match, err := u.ComparePasswordAndHash(password)
		if err != nil {
			log.Printf("Authenticate, ComparePasswordAndHash(), %v", err)
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

		secret, err := h.cs.JWTSecret()
		if err != nil {
			log.Printf("Authenticate, JWTSecret(), %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		token, err := secret.Sign(u.Role)
		if err != nil {
			log.Printf("Authenticate, Sign(), %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s", token)
	}
}
