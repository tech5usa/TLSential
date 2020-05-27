package ui

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
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

	// Handles both viewing create page and handling form action.
	r.HandleFunc("/ui/certificate/create", h.Authenticated(h.CreateCertificate())).Methods("GET", "POST")

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
			http.Redirect(w, r, "/ui/login", http.StatusTemporaryRedirect)
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
			http.Redirect(w, r, "/ui/dashboard", http.StatusTemporaryRedirect)
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

		http.Redirect(w, r, "/ui/dashboard", http.StatusTemporaryRedirect)
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

		http.Redirect(w, r, "/ui/login", http.StatusTemporaryRedirect)
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

// createCertTemplate holds variables for html template that renders the cert create page.
type createCertTemplate struct {
	Domains    string
	RenewAt    string
	Email      string
	CSRFField  template.HTML
	Validation certValidation
}

// certValidation holds any UI error strings that will need to be rendered if Creation fails.
type certValidation struct {
	Domains string
	RenewAt string
	Email   string
	Success string
	Error   string
}

// Serve /ui/certificate/create page.
func (h *uiHandler) CreateCertificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			cv := certValidation{}

			domains := strings.Split(r.FormValue("domains"), ",")
			email := r.FormValue("email")
			cert, err := model.NewCertificate(domains, email)
			if err != nil {
				if err == model.ErrInvalidDomains {
					cv.Domains = "One or more domains are not valid"
					cv.Error = "Fix invalid fields and try again."
					h.renderCreateCertificate(w, r, cv)
					return
				}
				if err == model.ErrInvalidEmail {
					cv.Email = "Submitted email address is not valid"
					cv.Error = "Fix invalid fields and try again."
					h.renderCreateCertificate(w, r, cv)
					return
				}
			}

			renewAt, err := strconv.Atoi(r.FormValue("renewAt"))
			if err != nil {
				cv.RenewAt = "Invalid RenewAt value"
				cv.Error = "Fix invalid fields and try again."
				h.renderCreateCertificate(w, r, cv)
				return
			}
			cert.RenewAt = renewAt
			err = h.certificateService.SaveCert(cert)
			if err != nil {
				log.Print(err.Error())
				http.Error(w, "oh dang", http.StatusInternalServerError)
				return
			}

			//We're not using RequestIssue because we always want this request to go through even if the
			//channel buffers are full.
			go func(id string) { h.acmeService.GetIssueChannel() <- id }(cert.ID)
			http.Redirect(w, r, "/ui/certificate/id/"+cert.ID, http.StatusSeeOther)
			return
		}
		h.renderCreateCertificate(w, r, certValidation{})
	}
}

func (h *uiHandler) renderCreateCertificate(w http.ResponseWriter, r *http.Request, cv certValidation) {

	t, err := template.ParseFiles("ui/templates/create_certificate.html")
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "oh boyyyy :(", http.StatusInternalServerError)
		return
	}

	p := createCertTemplate{
		Domains:    r.FormValue("domains"),
		RenewAt:    r.FormValue("renewAt"),
		Email:      r.FormValue("email"),
		CSRFField:  csrf.TemplateField(r),
		Validation: cv,
	}

	err = renderLayout(t, "Create New Certificate", p, w, r)
	if err != nil {
		log.Print(err.Error())
	}
}

// certTemplate holds the cert variable being rendered for the html template.
type certTemplate struct {
	Cert *model.Certificate
}

// Serve /ui/certificate/id/{id} page.
func (h *uiHandler) ViewCertificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		t, err := template.ParseFiles("ui/templates/view_certificate.html")
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

		p := certTemplate{
			cert,
		}

		err = renderLayout(t, fmt.Sprintf("Certificate - %s", cert.CommonName), p, w, r)
		if err != nil {
			log.Print(err.Error())
		}
	}
}

// Serve /ui/certificate/id/{id}/edit page.
func (h *uiHandler) SaveCertificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domains := r.FormValue("domains")
		renewAt := r.FormValue("renewAt")

		id := mux.Vars(r)["id"]

		cert, err := h.certificateService.Cert(id)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "whoops", http.StatusInternalServerError)
			return
		}

		cv := certValidation{}

		cert.RenewAt, err = strconv.Atoi(renewAt)
		if err != nil {
			cv.RenewAt = "Invalid RenewAt value"
			cv.Error = "Fix invalid fields and try again."
			h.renderCertificate(w, r, cv)
			return
		}

		cert.Domains = strings.Split(domains, ",")
		if !model.ValidDomains(cert.Domains) {
			cv.Domains = "One or more domains are not valid"
			cv.Error = "Fix invalid fields and try again."
			h.renderCertificate(w, r, cv)
			return
		}

		h.certificateService.SaveCert(cert)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "noooooo", http.StatusInternalServerError)
			return
		}

		if ok := h.acmeService.RequestRenew(cert.ID); !ok {
			log.Print("***WARNING*** Renew pipeline full...")
			http.Error(w, "whoops", http.StatusTooManyRequests)
			return
		}
		cv.Success = "Successfully saved certificate."
		http.Redirect(w, r, "/ui/certificate/id/"+cert.ID, http.StatusSeeOther)
	}
}

// editCertTemplate holds the variables for the html template that shows the cert edit page.
type editCertTemplate struct {
	ID         string
	CommonName string
	Domains    string
	RenewAt    int
	CSRFField  template.HTML
	Validation certValidation
}

// Serve /ui/certificate/id/{id}/edit page.
func (h *uiHandler) EditCertificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cv := certValidation{}
		h.renderCertificate(w, r, cv)
	}
}

func (h *uiHandler) renderCertificate(w http.ResponseWriter, r *http.Request, cv certValidation) {

	t, err := template.ParseFiles("ui/templates/edit_certificate.html")
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

	if cert == nil {
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}

	domains := strings.Join(cert.Domains, ",")
	p := editCertTemplate{
		ID:         cert.ID,
		CommonName: cert.CommonName,
		Domains:    domains,
		RenewAt:    cert.RenewAt,
		CSRFField:  csrf.TemplateField(r),
		Validation: cv,
	}

	err = renderLayout(t, fmt.Sprintf("Certificate - %s", cert.CommonName), p, w, r)

	if err != nil {
		log.Print(err.Error())
	}
}

// certListTemplate holds all certificates for parsing into html template.
type certListTemplate struct {
	Certs []*model.Certificate
}

// Serve /ui/certificates page.
func (h *uiHandler) ListCertificates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		t, err := template.ParseFiles("ui/templates/certificates.html")
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "uh oh", http.StatusInternalServerError)
			return
		}

		certs, err := h.certificateService.AllCerts()
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "yikes", http.StatusInternalServerError)
			return
		}

		p := certListTemplate{
			certs,
		}

		err = renderLayout(t, "Certificates", p, w, r)
		if err != nil {
			log.Print(err.Error())
		}
	}
}

// deleteCertTemplate holds variables for html template that renders the cert delete page.
type deleteCertTemplate struct {
	ID         string
	CommonName string
	CSRFField  template.HTML
}

// Serve /ui/certificate/create page.
func (h *uiHandler) DeleteCertificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			id := mux.Vars(r)["id"]
			err := h.certificateService.DeleteCert(id)
			if err != nil {
				log.Print(err.Error())
				http.Error(w, "schucks", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/ui/certificates", http.StatusSeeOther)
			return
		}
		h.renderDeleteCertificate(w, r)
	}
}

func (h *uiHandler) renderDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	files := []string{
		"ui/templates/layout.html",
		"ui/templates/head.html",
		"ui/templates/footer.html",
		"ui/templates/delete_certificate.html",
	}

	t, err := template.ParseFiles(files...)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "phooey", http.StatusInternalServerError)
		return
	}

	id := mux.Vars(r)["id"]

	cert, err := h.certificateService.Cert(id)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "gosh darn", http.StatusInternalServerError)
		return
	}

	if cert == nil {
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}

	p := deleteCertTemplate{
		ID:         cert.ID,
		CommonName: cert.CommonName,
		CSRFField:  csrf.TemplateField(r),
	}

	head := headTemplate{
		fmt.Sprintf("Delete Certificate"),
		h.mix("/css/site.css"),
		h.mix("/js/site.js"),
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
