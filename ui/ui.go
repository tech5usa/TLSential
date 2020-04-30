package ui

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

const localStaticDir = "./static"

// Handler provides an interface for all ui/calls.
type Handler interface {
	Route() *mux.Router
}

type uiHandler struct {
	Title string
}

func NewHandler(title string) Handler {
	return &uiHandler{title}
}

func (h *uiHandler) Route() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/ui/home", h.Home())
	r.HandleFunc("/ui/cert", h.Certificate())

	// TODO: Make sure this mostly always works no matter what working directory
	// is.
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(localStaticDir))))

	r.HandleFunc("/", h.Index())
	return r
}

func (h *uiHandler) Index() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("ui/templates/index.html")
		if err != nil {
			log.Print(err.Error())
		}
		t.Execute(w, h.Title)
	}
}

func (h *uiHandler) Certificate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("ui/templates/certificate.html")
		if err != nil {
			log.Print(err.Error())
		}
		t.Execute(w, h.Title)
	}
}

func (h *uiHandler) Home() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><head>%s</head><body><h1>%s</h1></body></html>", h.Title, h.Title)
	}
}
