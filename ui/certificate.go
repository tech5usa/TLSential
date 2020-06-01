package ui

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ImageWare/TLSential/model"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

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

	t, err := template.ParseFiles("ui/templates/delete_certificate.html")
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

	err = renderLayout(t, "Delete Certificate", p, w, r)
	if err != nil {
		log.Print(err.Error())
	}
}
