package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/ImageWare/TLSential/config"
	"github.com/ImageWare/TLSential/user"
	"github.com/gorilla/mux"
)

// TODO: Syslog formatted log/audit files.

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

// Handler provides an interface for all api/calls.
type Handler interface {
	Status() http.HandlerFunc
	Route() *mux.Router
}

type apiHandler struct {
	userHandler        UserHandler
	midHandler         MiddlewareHandler
	authHandler        AuthHandler
	configHandler      ConfigHandler
	challengeHandler   ChallengeHandler
	certificateHandler CertificateHandler
	Version            string
}

// NewHandler creates a new apiHandler with given UserService and ConfigService.
func NewHandler(version string, us user.Service, cs config.Service, chs challenge_config.Service, crs certificate.Service, as acme.Service) Handler {
	// TODO: Make RBAC persistent if needed.
	rbac := auth.InitRBAC()
	uh := NewUserHandler(us)
	mh := NewMiddlewareHandler(cs, rbac)
	ah := NewAuthHandler(cs, us)
	ch := NewConfigHandler(cs)
	chah := NewChallengeHandler(chs)
	crh := NewCertificateHandler(crs, as)
	return &apiHandler{userHandler: uh, midHandler: mh, authHandler: ah, configHandler: ch, challengeHandler: chah, certificateHandler: crh, Version: version}
}

// Status returns the current version of the server.
func (h *apiHandler) Status() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Version: %s", h.Version)
	}
}

// TODO: Break this up into sub routers within the handlers.
func (h *apiHandler) Route() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/api/status", h.Status())

	r.HandleFunc("/api/authenticate", h.authHandler.Authenticate()).Methods("POST")

	r.HandleFunc("/api/config/superadmin/{id}", h.configHandler.SuperAdmin()).Methods("POST")

	// api/certificate
	r.HandleFunc("/api/certificate",
		h.midHandler.Permission(
			auth.PermCertAdmin,
			h.certificateHandler.GetAll(),
		)).Methods("GET")

	r.HandleFunc("/api/certificate/{id}",
		h.midHandler.Permission(
			auth.PermCertAdmin,
			h.certificateHandler.Get(),
		)).Methods("GET")

	r.HandleFunc("/api/certificate",
		h.midHandler.Permission(
			auth.PermCertAdmin,
			h.certificateHandler.Post(),
		)).Methods("POST")

	r.HandleFunc("/api/certificate/{id}/cert",
		h.certificateHandler.GetCert(),
	).Methods("GET")

	r.HandleFunc("/api/certificate/{id}/privkey",
		h.certificateHandler.GetPrivkey(),
	).Methods("GET")

	r.HandleFunc("/api/certificate/{id}/issuer",
		h.certificateHandler.GetIssuer(),
	).Methods("GET")

	r.HandleFunc("/api/certificate/{id}/renew",
		h.certificateHandler.Renew(),
	).Methods("POST")

	// api/challenge
	r.HandleFunc("/api/challenge",
		h.midHandler.Permission(
			auth.PermChallengeAdmin,
			h.challengeHandler.Get(),
		)).Methods("GET")

	r.HandleFunc("/api/challenge",
		h.midHandler.Permission(
			auth.PermChallengeAdmin,
			h.challengeHandler.Put(),
		)).Methods("PUT")

	// api/user
	r.HandleFunc("/api/user/",
		h.midHandler.Permission(
			auth.PermUserRead,
			h.userHandler.Get(),
		)).Methods("GET")

	r.HandleFunc("/api/user/{id}",
		h.midHandler.Permission(
			auth.PermUserRead,
			h.userHandler.Get(),
		)).Methods("GET")

	r.HandleFunc("/api/user/",
		h.midHandler.Permission(
			auth.PermUserWrite,
			h.userHandler.Put(),
		)).Methods("PUT") // Funnel bad request for proper response.

	r.HandleFunc("/api/user/{id}",
		h.midHandler.Permission(
			auth.PermUserWrite,
			h.userHandler.Put(),
		)).Methods("PUT")

	r.HandleFunc("/api/user/",
		h.midHandler.Permission(
			auth.PermUserWrite,
			h.userHandler.Delete(),
		)).Methods("DELETE")

	r.HandleFunc("/api/user/{id}",
		h.midHandler.Permission(
			auth.PermUserWrite,
			h.userHandler.Delete(),
		)).Methods("DELETE")

	return r
}
