package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/config"
	"github.com/ImageWare/TLSential/user"
	"github.com/gorilla/mux"
)

var (
	// ErrMissingID is returned when you made a call that isn't supported
	// without an ID in the URI
	ErrMissingID = errors.New("Missing identifier in URI") // 400
	// ErrMismatchedID is returned when the post body doesn't match the URI
	ErrMismatchedID = errors.New("URI doesn't match provided data") // 400
	// ErrBodyRequired is returned if a request did not contain a body when one
	// was needed.
	ErrBodyRequired = errors.New("Body is required for this endpoint") // 400
)

type APIHandler interface {
	Status() http.HandlerFunc
	NewMux() *http.ServeMux
}

type apiHandler struct {
	uh      UserHandler
	mh      MiddlewareHandler
	ah      AuthHandler
	Version string
}

// NewAPIHandler creates a new apiHandler with given UserService and ConfigService.
func NewAPIHandler(version string, us user.Service, cs config.Service) APIHandler {
	// TODO: Make RBAC persistent if needed.
	rbac := auth.InitRBAC()
	uh := NewUserHandler(us)
	mh := NewMiddlewareHandler(cs, rbac)
	ah := NewAuthHandler(cs, us)
	return &apiHandler{uh: uh, mh: mh, ah: ah, Version: version}
}

// TODO: Take a server object so we can display a version number.
func (h *apiHandler) Status() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Version: %s", h.Version)
	}
}

// TODO: Break this up into sub routers within the handlers.
func (h *apiHandler) router() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/status", h.Status())

	r.HandleFunc("/api/authenticate", h.ah.Authenticate()).Methods("POST")

	r.HandleFunc("/api/user/",
		h.mh.Permission(
			auth.PermUserRead,
			h.uh.Get(),
		)).Methods("GET")

	r.HandleFunc("/api/user/",
		h.mh.Permission(
			auth.PermUserWrite,
			h.uh.Put(),
		)).Methods("PUT") // Funnel bad request for proper response.

	r.HandleFunc("/api/user/",
		h.mh.Permission(
			auth.PermUserWrite,
			h.uh.Delete(),
		)).Methods("DELETE")

	r.HandleFunc("/api/user/{id}",
		h.mh.Permission(
			auth.PermUserRead,
			h.uh.Get(),
		)).Methods("GET")

	r.HandleFunc("/api/user/{id}",
		h.mh.Permission(
			auth.PermUserWrite,
			h.uh.Put(),
		)).Methods("PUT")

	r.HandleFunc("/api/user/{id}",
		h.mh.Permission(
			auth.PermUserWrite,
			h.uh.Delete(),
		)).Methods("DELETE")

	return r
}

// NewMux returns a new http.ServeMux with established routes.
func (h *apiHandler) NewMux() *http.ServeMux {
	r := h.router()

	s := http.NewServeMux()
	s.Handle("/", r)
	return s
}
