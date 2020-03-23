package api

import (
	"github.com/ImageWare/TLSential/auth"

	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// TODO: Take a server object so we can display a version number.
func statusHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", "I'm online D:")
	}
}

// TODO: Break this up into UserAppController, etc.
func router(sc *ServerContext) *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/status", statusHandler())

	r.HandleFunc("/api/authenticate", AuthHandler(sc)).Methods("POST")

	r.HandleFunc("/api/user/",
		sc.Permission(
			auth.PermUserRead,
			userGETHandler(sc),
		)).Methods("GET")

	r.HandleFunc("/api/user/",
		sc.Permission(
			auth.PermUserWrite,
			userPUTHandler(sc),
		)).Methods("PUT") // Funnel bad request for proper response.

	r.HandleFunc("/api/user/",
		sc.Permission(
			auth.PermUserWrite,
			userDELETEHandler(sc),
		)).Methods("DELETE")

	r.HandleFunc("/api/user/{id}",
		sc.Permission(
			auth.PermUserRead,
			userGETHandler(sc),
		)).Methods("GET")

	r.HandleFunc("/api/user/{id}",
		sc.Permission(
			auth.PermUserWrite,
			userPUTHandler(sc),
		)).Methods("PUT")

	r.HandleFunc("/api/user/{id}",
		sc.Permission(
			auth.PermUserWrite,
			userDELETEHandler(sc),
		)).Methods("DELETE")

	return r
}

// NewMux returns a new http.ServeMux with established routes.
func NewMux(sc *ServerContext) *http.ServeMux {
	r := router(sc)

	s := http.NewServeMux()
	s.Handle("/", r)
	return s
}
