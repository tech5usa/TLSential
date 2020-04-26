package ui

import (
	"fmt"
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

	return r
}

func (h *uiHandler) Home() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><head>%s</head><body><h1>%s</h1></body></html>", h.Title, h.Title)
	}
}
