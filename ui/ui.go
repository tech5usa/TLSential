package ui

import (
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
	"github.com/ImageWare/TLSential/user"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

const cookieName = "tlsential"

// Handler provides an interface for all ui/calls.
// TODO: Rename to Router or make method Handle. A Router should Route, etc.
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

// NewHandler returns a new UI Handler for use in main.
func NewHandler(version string, us user.Service, cs config.Service, chs challenge_config.Service, crs certificate.Service, as acme.Service) Handler {
	key, err := cs.SessionKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	store := sessions.NewCookieStore(key)
	return &uiHandler{version, us, cs, chs, crs, as, store}
}

// Route returns a handler for all /ui/ routes.
func (h *uiHandler) Route(unsafe bool) http.Handler {
	key, err := h.configService.SessionKey()
	if err != nil {
		log.Fatal(err.Error())
	}

	CSRF := csrf.Protect(
		key,
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.FieldName("csrf_token"),
		csrf.Secure(!unsafe), // If unsafe, we pass in FALSE for secure.
	)

	r := mux.NewRouter()
	r.HandleFunc("/ui/dashboard", h.Authenticated(h.Dashboard())).Methods("GET")
	r.HandleFunc("/ui/certificates", h.Authenticated(h.ListCertificates())).Methods("GET")
	r.HandleFunc("/ui/certificate/id/{id}", h.Authenticated(h.ViewCertificate())).Methods("GET")
	r.HandleFunc("/ui/certificate/id/{id}/edit", h.Authenticated(h.EditCertificate())).Methods("GET")
	r.HandleFunc("/ui/certificate/id/{id}/edit", h.Authenticated(h.SaveCertificate())).Methods("POST")
	r.HandleFunc("/ui/certificate/id/{id}/delete", h.Authenticated(h.DeleteCertificate())).Methods("GET", "POST")
	r.HandleFunc("/ui/certificate/create", h.Authenticated(h.CreateCertificate())).Methods("GET", "POST")

	r.HandleFunc("/ui/users", h.Authenticated(h.ListUsers())).Methods("GET")
	r.HandleFunc("/ui/user/id/{id}", h.Authenticated(h.ViewUser())).Methods("GET")
	r.HandleFunc("/ui/user/id/{id}/edit", h.Authenticated(h.EditUser())).Methods("GET")
	r.HandleFunc("/ui/user/id/{id}/edit", h.Authenticated(h.SaveUser())).Methods("POST")
	r.HandleFunc("/ui/user/id/{id}/delete", h.Authenticated(h.DeleteUser())).Methods("GET", "POST")
	r.HandleFunc("/ui/user/create", h.Authenticated(h.CreateUser())).Methods("GET", "POST")

	r.HandleFunc("/ui/login", h.GetLogin()).Methods("GET")
	r.HandleFunc("/ui/login", h.PostLogin()).Methods("POST")
	r.HandleFunc("/ui/logout", h.Logout()).Methods("POST")

	return CSRF(r)
}

// Authenticated is a middleware that ensures the user is authenticated, otherwise redirects them to the login page.
func (h *uiHandler) Authenticated(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, cookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
			return
		}
		f(w, r)
	}
}

// layoutTemplate provides needed variables for the overall layout of the page.
type layoutTemplate struct {
	Head      headTemplate
	C         interface{}
	CSRFField template.HTML
}

// headTemplate provides needed variables for the html template that renders the <head> portion of the page.
type headTemplate struct {
	Title         string
	CustomCSSFile string
	CustomJSFile  string
}

// loginTemplate provides necessary variables for the html template that renders the login page.
type loginTemplate struct {
	Head      headTemplate
	Error     string
	CSRFField template.HTML
}

// renderLogin parses the necessary template for the login page given the required variables.
func (h *uiHandler) renderLogin(w http.ResponseWriter, r *http.Request, uiError string) {
	t, err := template.ParseGlob("ui/templates/*.html")
	if err != nil {
		log.Print(err.Error())
	}
	head := headTemplate{"Login", mix("/css/site.css"), mix("/js/site.js")}
	p := loginTemplate{head, uiError, csrf.TemplateField(r)}
	err = t.ExecuteTemplate(w, "login", p)
	if err != nil {
		log.Print(err.Error())
	}
}

// GetLogin displays the login page on first request.
func (h *uiHandler) GetLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, cookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Check if user is authenticated, if so send them to dashboard.
		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			http.Redirect(w, r, "/ui/dashboard", http.StatusSeeOther)
			return
		}
		h.renderLogin(w, r, "")
	}
}

// PostLogin handles authentication and either redirects to dashboard or shows error to login page.
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

		session, err := h.store.Get(r, cookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// TODO: Add role and maybe username here.
		// Set user as authenticated
		session.Values["authenticated"] = true
		session.Save(r, w)

		http.Redirect(w, r, "/ui/dashboard", http.StatusSeeOther)
	}
}

// Logout unauthenticates a user and redirects to login page.
func (h *uiHandler) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		session, err := h.store.Get(r, cookieName)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Set user as NOT authenticated
		session.Values["authenticated"] = false
		session.Save(r, w)

		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
	}
}

func renderLayout(t *template.Template, title string, C interface{}, w http.ResponseWriter, r *http.Request) error {
	t, err := t.ParseFiles("ui/templates/layout.html", "ui/templates/head.html", "ui/templates/footer.html")

	if err != nil {
		return err
	}

	head := headTemplate{title, mix("/css/site.css"), mix("/js/site.js")}

	l := layoutTemplate{head, C, csrf.TemplateField(r)}

	return t.ExecuteTemplate(w, "layout", l)

}

// dashboardTemplate stores necessary variables for the html template
type dashboardTemplate struct {
	TotalCerts        int
	TotalRenewedCerts int
	TotalDomains      int
}

// Serve /ui/dashboard page.
func (h *uiHandler) Dashboard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		t, err := template.ParseFiles("ui/templates/dashboard.html")

		if err != nil {
			log.Print(err.Error())
		}

		d := dashboardTemplate{4, 20, 69}

		err = renderLayout(t, "Dashboard", d, w, r)

		if err != nil {
			log.Print(err.Error())
		}
	}
}

var loadedHot bool
var hotHost string

// Prepend a given asset path with the appropriate HMR url if available
func mix(asset string) string {
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
