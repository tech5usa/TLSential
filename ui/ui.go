package ui

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/model"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// Handler provides an interface for all ui/calls.
type Handler interface {
	Route() *mux.Router
}

type uiHandler struct {
	Title              string
	certificateService certificate.Service
	store              *sessions.CookieStore
}

func NewHandler(title string, cs certificate.Service) Handler {
	return &uiHandler{title, cs}
}

func (h *uiHandler) Route() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/ui/dashboard", h.Dashboard())
	r.HandleFunc("/ui/cert/{id}", h.Certificate())
	r.HandleFunc("/ui/login", h.Login())
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
	Head headTemplate
}

func (h *uiHandler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseGlob("ui/templates/*.html")
		if err != nil {
			log.Print(err.Error())
		}
		head := headTemplate{"Login", "site.css"}
		p := loginTemplate{head}
		err = t.ExecuteTemplate(w, "login", p)
		if err != nil {
			log.Print(err.Error())
		}
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
