package ui

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/ImageWare/TLSential/config"
	"github.com/ImageWare/TLSential/model"
	"github.com/ImageWare/TLSential/user"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

const CookieName = "tlsential"

// Handler provides an interface for all ui/calls.
type Handler interface {
	Route() *mux.Router
}

type uiHandler struct {
	Version            string
	userService        user.Service
	configService      config.Service
	challengeService   challenge_config.Service
	certificateService certificate.Service
	acmeService        acme.Service
	store              *sessions.CookieStore
}

func NewHandler(version string, us user.Service, cs config.Service, chs challenge_config.Service, crs certificate.Service, as acme.Service) Handler {
	key, err := cs.SessionKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	store := sessions.NewCookieStore(key)
	return &uiHandler{version, us, cs, chs, crs, as, store}
}

func (h *uiHandler) Route() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/ui/dashboard", h.Authenticated(h.Dashboard()))
	r.HandleFunc("/ui/cert/{id}", h.Authenticated(h.Certificate()))
	r.HandleFunc("/ui/login", h.GetLogin()).Methods("GET")
	r.HandleFunc("/ui/login", h.PostLogin()).Methods("POST")

	return r
}

type headTemplate struct {
	Title         string
	CustomCSSFile string
}

type layoutTemplate struct {
	Head headTemplate
	C    interface{}
}

type loginTemplate struct {
	Head  headTemplate
	Error string
}

func (h *uiHandler) Authenticated(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, CookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/ui/login", http.StatusTemporaryRedirect)
			return
		}
		f(w, r)
	}
}

func (h *uiHandler) GetLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.renderLogin(w, "")
	}
}

func (h *uiHandler) renderLogin(w http.ResponseWriter, uiError string) {
	t, err := template.ParseGlob("ui/templates/*.html")
	if err != nil {
		log.Print(err.Error())
	}
	head := headTemplate{"Login", "site.css"}
	p := loginTemplate{head, uiError}
	t.ExecuteTemplate(w, "login", p)
}

func (h *uiHandler) PostLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Print("what what")

		r.ParseForm()
		username := r.Form["username"]
		password := r.Form["password"]

		var uiError string

		u, err := h.userService.GetUser(username)
		if err != nil {
			log.Print(err)
			uiError = "Server error. Please try again later."
			log.Print(uiError)

			h.renderLogin(w, uiError)
			return
		}

		if u == nil {
			uiError = "User not found."
			log.Print(uiError)

			h.renderLogin(w, uiError)
			return
		}

		match, err := u.ComparePasswordAndHash(password)
		if err != nil {
			log.Print(err)
			uiError = "Server error. Please try again later."
			log.Print(uiError)

			h.renderLogin(w, uiError)
			return
		}

		if !match {
			uiError = "Invalid credentials."
			log.Print(uiError)
			h.renderLogin(w, uiError)
			return
		}

		session, err := h.store.Get(r, CookieName)
		if err != nil {
			log.Fatal(err.Error())
		}
		// TODO: Add role and maybe username here.
		// Set user as authenticated
		session.Values["authenticated"] = true
		session.Save(r, w)

		// TODO: Add logout functionality.
		log.Print("auth'd")
		http.Redirect(w, r, "/ui/dashboard", http.StatusTemporaryRedirect)
	}
}

type dashboardTemplate struct {
	TotalCerts        int
	TotalRenewedCerts int
	TotalDomains      int
}

// Serve /ui/dashboard page.
func (h *uiHandler) Dashboard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		files := []string{
			"ui/templates/layout.html",
			"ui/templates/head.html",
			"ui/templates/footer.html",
			"ui/templates/dashboard.html",
		}
		t, err := template.ParseFiles(files...)
		if err != nil {
			log.Print(err.Error())
		}
		head := headTemplate{"Dashboard", "site.css"}

		// TODO: Fill out appropriate data for cert, renewed cert, and domain counts.
		d := dashboardTemplate{4, 20, 69}
		l := layoutTemplate{head, d}

		err = t.ExecuteTemplate(w, "layout", l)
		if err != nil {
			log.Print(err.Error())
		}
	}
}

type certTemplate struct {
	Cert *model.Certificate
}

// Serve /ui/certificate page.
func (h *uiHandler) Certificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		files := []string{
			"ui/templates/layout.html",
			"ui/templates/head.html",
			"ui/templates/footer.html",
			"ui/templates/certificate.html",
		}
		t, err := template.ParseFiles(files...)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "drats", http.StatusInternalServerError)
			return
		}

		id := mux.Vars(r)["id"]

		cert, err := h.certificateService.Cert(id)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "whoops", http.StatusInternalServerError)
			return
		}

		head := headTemplate{
			fmt.Sprintf("Certificate - %s", cert.CommonName),
			"site.css",
		}
		p := certTemplate{
			cert,
		}
		l := layoutTemplate{
			head,
			p,
		}
		err = t.ExecuteTemplate(w, "layout", l)
		if err != nil {
			log.Print(err.Error())
		}
	}
}
