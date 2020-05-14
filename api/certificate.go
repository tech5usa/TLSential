package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/model"

	"github.com/gorilla/mux"
)

const CertFileExt = ".crt"
const IssuerCertFileExt = ".issuer.crt"
const KeyFileExt = ".key"
const PemFileExt = ".pem"

type CertificateHandler interface {
	GetAll() http.HandlerFunc
	Get() http.HandlerFunc
	Post() http.HandlerFunc
	Delete() http.HandlerFunc
	DeleteAll() http.HandlerFunc
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
	RenewAt int
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
	RenewAt       int
	Issued        bool
	LastError     string
	ACMEEmail     string
	ModTime       time.Time
}

// TODO: Add validation function to make sure domains are actual domains.

// TODO: Refactor sys logging to be more consistent and easier.

func (h *certHandler) DeleteAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h.cs.DeleteAllCerts()
		if err != nil {
			log.Printf("apiCertHandler DELETE, DeleteAllCerts(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
}

// Delete handles all delete calls to api/certificate
func (h *certHandler) Delete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

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

func (h *certHandler) GetAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		certs, err := h.cs.AllCerts()
		if err != nil {
			log.Printf("api CertHandler Get(), GetAllCerts(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var crs = make([]*CertResp, 0)

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
				RenewAt:       c.RenewAt,
				Issued:        c.Issued,
				LastError:     lastError,
				ACMEEmail:     c.ACMEEmail,
				ModTime:       c.ModTime,
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
	}
}

func (h *certHandler) Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		// "/api/certificate/"
		if id == "" {
			log.Printf("api CertHandler GetCert(), should never have routed here")
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
			RenewAt:       c.RenewAt,
			Issued:        c.Issued,
			LastError:     lastError,
			ACMEEmail:     c.ACMEEmail,
			ModTime:       c.ModTime,
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
		creq := &CertReq{
			RenewAt: model.DefaultRenewAt, //Set a default value for RenewAt
		}
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

		reg, err := h.acme.Register(c)

		if err != nil {
			log.Printf("api CertHandler POST, acme.Register(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c.ACMERegistration = reg

		//TODO: Should probably decide valid range for client supplied RenewAt value
		//For instance we may not want them to be able to specify 0 or less, as that would
		//cause the cert to never auto renew. Although maybe thats a valid use case?
		//We may also not want them to be able to specify a time as long or longer than the certs lifetime
		//as that would cause to autorenew every time autoRenewal is run.
		c.RenewAt = creq.RenewAt

		// Save to database
		err = h.cs.SaveCert(c)
		if err != nil {
			log.Printf("api CertHandler POST, SaveCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//We're not using RequestIssue because we always want this request to go through even if the
		//channel buffers are full.
		go func(id string) { h.acme.GetIssueChannel() <- id }(c.ID)

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
			RenewAt:       c.RenewAt,
			Issued:        c.Issued,
			LastError:     "",
			ACMEEmail:     c.ACMEEmail,
			ModTime:       c.ModTime,
		}

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")

		err = json.NewEncoder(w).Encode(cresp)
		if err != nil {
			log.Printf("apiCertHandler POST, json.Marshal(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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

		modtime := c.ModTime
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

		modtime := c.ModTime
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

		// Secrets are one time use for downloading PrivKeys.
		c.Secret = auth.NewPassword()
		err = h.cs.SaveCert(c)
		if err != nil {
			log.Printf("apiCertHandler GET PrivKey, SaveCert(), %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		modtime := c.ModTime
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

		if !h.acme.RequestRenew(c.ID) {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		w.WriteHeader(http.StatusAccepted)
	}
}
