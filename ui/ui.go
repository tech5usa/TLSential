package ui

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/ImageWare/TLSential/config"
	"github.com/ImageWare/TLSential/model"
	"github.com/ImageWare/TLSential/user"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

const CookieName = "tlsential"

// Handler provides an interface for all ui/calls.
type Handler interface {
	Route(bool) http.Handler
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

func (h *uiHandler) Route(unsafe bool) http.Handler {
	key, err := h.configService.SessionKey()
	if err != nil {
		log.Fatal(err.Error())
	}

	var CSRF func(http.Handler) http.Handler

	CSRF = csrf.Protect(
		key,
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.FieldName("csrf_token"),
		csrf.Secure(!unsafe), // If unsafe, we pass in FALSE for secure.
	)

	r := mux.NewRouter()
	r.HandleFunc("/ui/dashboard", h.Authenticated(h.Dashboard()))
	r.HandleFunc("/ui/cert/{id}", h.Authenticated(h.Certificate()))
	r.HandleFunc("/ui/login", h.GetLogin()).Methods("GET")
	r.HandleFunc("/ui/login", h.PostLogin()).Methods("POST")
	r.HandleFunc("/ui/logout", h.Logout()).Methods("POST")

	return CSRF(r)
}

type headTemplate struct {
	Title         string
	CustomCSSFile string
	CustomJSFile  string
}

type layoutTemplate struct {
	Head      headTemplate
	C         interface{}
	CSRFField template.HTML
}

type loginTemplate struct {
	Head      headTemplate
	Error     string
	CSRFField template.HTML
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
		session, err := h.store.Get(r, CookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Check if user is authenticated, if so send them to dashboard.
		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			http.Redirect(w, r, "/ui/dashboard", http.StatusTemporaryRedirect)
			return
		}
		h.renderLogin(w, r, "")
	}
}

func (h *uiHandler) renderLogin(w http.ResponseWriter, r *http.Request, uiError string) {
	t, err := template.ParseGlob("ui/templates/*.html")
	if err != nil {
		log.Print(err.Error())
	}
	head := headTemplate{"Login", h.mix("/css/site.css"), h.mix("/js/site.js")}
	p := loginTemplate{head, uiError, csrf.TemplateField(r)}
	err = t.ExecuteTemplate(w, "login", p)
	if err != nil {
		log.Print(err.Error())
	}
}

func (h *uiHandler) PostLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var uiError string

		u, err := h.userService.GetUser(username)
		if err != nil {
			log.Print(err)
			uiError = "Server error. Please try again later."
			h.renderLogin(w, r, uiError)
			return
		}

		if u == nil {
			uiError = "User not found."
			h.renderLogin(w, r, uiError)
			return
		}

		match, err := u.ComparePasswordAndHash(password)
		if err != nil {
			log.Print(err)
			uiError = "Server error. Please try again later."
			h.renderLogin(w, r, uiError)
			return
		}

		if !match {
			uiError = "Invalid credentials."
			h.renderLogin(w, r, uiError)
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

		http.Redirect(w, r, "/ui/dashboard", http.StatusTemporaryRedirect)
	}
}

func (h *uiHandler) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		session, err := h.store.Get(r, CookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Set user as NOT authenticated
		session.Values["authenticated"] = false
		session.Save(r, w)

		http.Redirect(w, r, "/ui/login", http.StatusTemporaryRedirect)
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
		head := headTemplate{"Dashboard", h.mix("/css/site.css"), h.mix("/js/site.js")}

		// TODO: Fill out appropriate data for cert, renewed cert, and domain counts.
		d := dashboardTemplate{4, 20, 69}
		l := layoutTemplate{head, d, csrf.TemplateField(r)}

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
			h.mix("/css/site.css"),
			h.mix("/js/site.js"),
		}
		p := certTemplate{
			cert,
		}
		l := layoutTemplate{
			head,
			p,
			csrf.TemplateField(r),
		}
		err = t.ExecuteTemplate(w, "layout", l)
		if err != nil {
			log.Print(err.Error())
		}
	}
}

var loadedHot bool
var hotHost string

// Prepend a given asset path with the appropriate HMR url if available
func (h *uiHandler) mix(asset string) string {
	if loadedHot == false {
		// Memoize the fact that we've loaded early
		loadedHot = true

		// Resolve the CWD
		dir, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// Resolve the contents of the hot file
		host, err := ioutil.ReadFile(dir + "/static/hot")
		if err == nil {
			hotHost = strings.TrimSpace(string(host))
		}
	}

	// If we actually have a hothost defined, prepend it to the given asset
	if hotHost != "" {
		return hotHost + asset
	}

	// Otherwise prepend the static directory
	return "/static" + asset
}
