package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/model"

	"github.com/gorilla/mux"
)

const CertFileExt = ".crt"
const IssuerCertFileExt = ".issuer.crt"
const KeyFileExt = ".key"
const PemFileExt = ".pem"

type CertificateHandler interface {
	Get() http.HandlerFunc
	Post() http.HandlerFunc
	Delete() http.HandlerFunc
	GetCert() http.HandlerFunc
	GetPrivkey() http.HandlerFunc
	GetIssuer() http.HandlerFunc
	Renew() http.HandlerFunc
}

type certHandler struct {
	cs   certificate.Service
	acme acme.Service
}

func NewCertificateHandler(cs certificate.Service, as acme.Service) CertificateHandler {
	return &certHandler{cs, as}
}

// CertReq is used for parsing API input
type CertReq struct {
	Domains []string
	Email   string
}

// CertResp is used for exporting User data via API responses
type CertResp struct {
	ID            string
	Secret        string
	CommonName    string
	Domains       []string
	CertURL       string
	CertStableURL string
	Expiry        time.Time
	Issued        bool
	LastError     string
	ACMEEmail     string
}

// TODO: Add validation function to make sure domains are actual domains.

// TODO: Refactor sys logging to be more consistent and easier.

// Delete handles all delete calls to api/certificate
func (h *certHandler) Delete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		// DELETE /api/certificate/
		// Delete all certs
		if id == "" {
			err := h.cs.DeleteAllCerts()
			if err != nil {
				log.Printf("apiCertHandler DELETE, DeleteAllCerts(), %s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Delete cert
		u, err := h.cs.Cert(id)
		if err != nil {
			log.Printf("apiCertHandler DELETE, GetCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If it doesn't already exist, return 404.
		if u == nil {
			w.WriteHeader(http.StatusNotFound)
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		err = h.cs.DeleteCert(id)
		if err != nil {
			log.Printf("apiCertHandler DELETE, DeleteCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

}

func (h *certHandler) Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		// TODO: Factor out this section into new handler with separate
		// permissions

		// "/api/certificate/"
		if id == "" {
			certs, err := h.cs.AllCerts()
			if err != nil {
				log.Printf("api CertHandler Get(), GetAllCerts(), %s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var crs []*CertResp

			for _, c := range certs {
				var lastError string
				if c.LastError != nil {
					lastError = c.LastError.Error()
				}
				cr := &CertResp{
					ID:            c.ID,
					Secret:        c.Secret,
					CommonName:    c.CommonName,
					Domains:       c.Domains,
					CertURL:       c.CertURL,
					CertStableURL: c.CertStableURL,
					Expiry:        c.Expiry,
					Issued:        c.Issued,
					LastError:     lastError,
					ACMEEmail:     c.ACMEEmail,
				}
				crs = append(crs, cr)
			}

			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")

			err = json.NewEncoder(w).Encode(crs)
			if err != nil {
				log.Printf("apiCertHandler GET ALL, json.Encode(), %s", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		// Return cert if found
		c, err := h.cs.Cert(id)
		if err != nil {
			log.Printf("apiCertHandler GET, GetCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if c == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		// Make an appropriate response object (ie. pkey returned)
		var lastError string
		if c.LastError != nil {
			lastError = c.LastError.Error()
		}
		cr := &CertResp{
			ID:            c.ID,
			Secret:        c.Secret,
			CommonName:    c.CommonName,
			Domains:       c.Domains,
			CertURL:       c.CertURL,
			CertStableURL: c.CertStableURL,
			Expiry:        c.Expiry,
			Issued:        c.Issued,
			LastError:     lastError,
			ACMEEmail:     c.ACMEEmail,
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")

		err = json.NewEncoder(w).Encode(cr)
		if err != nil {
			log.Printf("apiCertHandler GET, json.Encode(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (h *certHandler) Post() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Body == nil {
			http.Error(w, ErrBodyRequired.Error(), http.StatusBadRequest)
			return
		}

		// Decode JSON payload
		creq := &CertReq{}
		err := json.NewDecoder(r.Body).Decode(creq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create new Certificate obj.
		// TODO: Not all errors are Server Errors.
		c, err := model.NewCertificate(creq.Domains, creq.Email)
		if err != nil {
			log.Printf("api CertHandler POST, NewCertificate(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Save to database
		err = h.cs.SaveCert(c)
		if err != nil {
			log.Printf("api CertHandler POST, SaveCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		go h.acme.Trigger(c.ID)

		// Build a response obj to return, specifically leaving out
		// Keys and Certs
		cresp := &CertResp{
			ID:            c.ID,
			Secret:        c.Secret,
			CommonName:    c.CommonName,
			Domains:       c.Domains,
			CertURL:       c.CertURL,
			CertStableURL: c.CertStableURL,
			Expiry:        c.Expiry,
			Issued:        c.Issued,
			LastError:     "",
			ACMEEmail:     c.ACMEEmail,
		}
		out, err := json.Marshal(cresp)
		if err != nil {
			log.Printf("apiCertHandler POST, json.Marshal(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%s", out)
	}
}

// TODO: Refactor GetCert, GetIssuer, and GetPrivkey as they do almost the exact
// same things.

// /api/certificate/{id}/cert
func (h *certHandler) GetCert() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		if id == "" {
			log.Printf("api CertHandler GetCert, should never have routed here")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Return cert if found
		c, err := h.cs.Cert(id)
		if err != nil {
			log.Printf("apiCertHandler GET, GetCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if c == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		if !c.Issued {
			http.Error(w, "certificate not issued", http.StatusBadRequest)
			return
		}

		secret, ok := getSecret(r)
		if !ok || secret != c.Secret {
			// https://tools.ietf.org/html/rfc7235#section-3.1
			w.Header().Set("WWW-Authenticate", "Secret")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		modtime := time.Now()
		filename := fmt.Sprintf("%s%s", c.CommonName, CertFileExt)
		cd := fmt.Sprintf("attachment; filename=%s", filename)

		w.Header().Add("Content-Disposition", cd)
		http.ServeContent(w, r, filename, modtime, bytes.NewReader(c.Certificate))
	}
}

// /api/certificate/{id}/issuer
func (h *certHandler) GetIssuer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		if id == "" {
			log.Printf("api CertHandler GetIssuer, should never have routed here")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Return cert if found
		c, err := h.cs.Cert(id)
		if err != nil {
			log.Printf("apiCertHandler GET, GetCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if c == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		if !c.Issued {
			http.Error(w, "certificate not issued", http.StatusBadRequest)
			return
		}

		secret, ok := getSecret(r)
		if !ok || secret != c.Secret {
			// https://tools.ietf.org/html/rfc7235#section-3.1
			w.Header().Set("WWW-Authenticate", "Secret")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		modtime := time.Now()
		filename := fmt.Sprintf("%s%s", c.CommonName, IssuerCertFileExt)
		cd := fmt.Sprintf("attachment; filename=%s", filename)

		w.Header().Add("Content-Disposition", cd)
		http.ServeContent(w, r, filename, modtime, bytes.NewReader(c.IssuerCertificate))
	}
}

// /api/certificate/{id}/privkey
func (h *certHandler) GetPrivkey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		if id == "" {
			log.Printf("api CertHandler GetPrivkey, should never have routed here")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Return cert if found
		c, err := h.cs.Cert(id)
		if err != nil {
			log.Printf("apiCertHandler GET, GetCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if c == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		if !c.Issued {
			http.Error(w, "certificate not issued", http.StatusBadRequest)
			return
		}

		secret, ok := getSecret(r)
		if !ok || secret != c.Secret {
			// https://tools.ietf.org/html/rfc7235#section-3.1
			w.Header().Set("WWW-Authenticate", "Secret")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		modtime := time.Now()
		filename := fmt.Sprintf("%s%s", c.CommonName, KeyFileExt)
		cd := fmt.Sprintf("attachment; filename=%s", filename)

		w.Header().Add("Content-Disposition", cd)
		http.ServeContent(w, r, filename, modtime, bytes.NewReader(c.PrivateKey))
	}
}

func (h *certHandler) Renew() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		if id == "" {
			log.Printf("api CertHandler Renew(), should never have routed here")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Return cert if found
		c, err := h.cs.Cert(id)
		if err != nil {
			log.Printf("api CertHandler Renew(), GetCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if c == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		if !c.Issued {
			http.Error(w, "certificate not issued", http.StatusBadRequest)
			return
		}

		secret, ok := getSecret(r)
		if !ok || secret != c.Secret {
			// https://tools.ietf.org/html/rfc7235#section-3.1
			w.Header().Set("WWW-Authenticate", "Secret")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		go h.acme.Renew(c)

		w.WriteHeader(http.StatusAccepted)
	}
}
