package ui

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

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

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	r.HandleFunc("/", h.Index())
	return r
}

func fileServe(w http.ResponseWriter, r *http.Request) {
	log.Print(w)
	log.Print(r)
	path := fmt.Sprintf("static%s", r.URL.Path)
	log.Print(path)
	http.ServeFile(w, r, path)
}

func (h *uiHandler) Index() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Print(r)
		t, err := template.ParseFiles("ui/templates/index.html")
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
