package api

import (
	"net/http"
	"strings"

	rbac "github.com/mikespook/gorbac"
)

// Permission is a middleware that checks that the request includes an JWT with appropriate permissions for this request.
func (sc *ServerContext) Permission(p rbac.Permission, h http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Swap with Go's stdlib version of parsing this header
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(auth) != 2 || auth[0] != "Bearer" {
			// https://tools.ietf.org/html/rfc7235#section-3.1
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// auth[1] is the JWT at this point
		claims, err := sc.JWTSecret.Validate(auth[1])
		if err != nil {
			// TODO: See what error might be returned, might not be good to
			// divulge
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		role := claims["role"].(string)
		if !sc.RBAC.IsGranted(role, p, nil) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	}
}
