package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/ImageWare/TLSential/model"
)

var (
	ErrInvalidAuthEmail = errors.New("auth email cannot be blank")
	ErrInvalidAuthKey   = errors.New("auth key cannot be blank")
)

// ChallengeHandler provides endpoints for all api/config/ calls.
// TODO: Change this to a "Handle" func only, abstract from there.
type ChallengeHandler interface {
	Get() http.HandlerFunc
	Put() http.HandlerFunc
}

type challengeHandler struct {
	cs challenge_config.Service
}

// NewChallengeHandler takes a config.Service and returns a working ConfigHandler.
func NewChallengeHandler(cs challenge_config.Service) ChallengeHandler {
	return &challengeHandler{cs}
}

// Get responds to the api/challenge endpoint.
func (h *challengeHandler) Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		c, err := h.cs.Auth()
		if err != nil {
			log.Printf("challengeHandlerGET, Auth(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		out, err := json.Marshal(c)
		if err != nil {
			log.Printf("challengeHandlerGET, json.Marshal(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s", out)
	}
}

func (h *challengeHandler) Put() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Must have a body
		if r.Body == nil {
			http.Error(w, ErrBodyRequired.Error(), http.StatusBadRequest)
			return
		}

		// Decode JSON payload
		creq := &model.ChallengeConfig{}
		err := json.NewDecoder(r.Body).Decode(creq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Make sure payload is mostly valid
		if creq.AuthEmail == "" {
			http.Error(w, ErrInvalidAuthEmail.Error(), http.StatusBadRequest)
			return
		}

		if creq.AuthKey == "" {
			http.Error(w, ErrInvalidAuthKey.Error(), http.StatusBadRequest)
			return
		}

		// Save to database
		err = h.cs.SetAuth(creq.AuthEmail, creq.AuthKey)
		if err != nil {
			log.Printf("challengeHandlerPUT, SetAuth(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
