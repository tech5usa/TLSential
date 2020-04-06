package service

import (
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/model"
)

type certService struct {
	cr certificate.Repository
}

// NewCertificateService returns a new service object with the associated Repo.
func NewCertificateService(cr certificate.Repository) certificate.Service {
	return &certService{cr}
}

// AllCerts returns a list of all Cert objects stored in the repo.
func (cs *certService) AllCerts() ([]*model.Certificate, error) {
	return cs.AllCerts()
}

// Cert takes an id and returns their whole cert object.
func (cs *certService) Cert(id string) (*model.Certificate, error) {
	return cs.Cert(id)
}

// SaveCert persists a Cert in BoltStore.
func (cs *certService) SaveCert(c *model.Certificate) error {
	return cs.SaveCert(c)
}

// DeleteCert removes any saved Cert object matching the id
func (cs *certService) DeleteCert(id string) error {
	return cs.DeleteCert(id)
}

// DeleteAllCerts deletes the Bolt bucket holding certs and recreates
// it, essentially deleting all objects.
func (cs *certService) DeleteAllCerts() error {
	return cs.DeleteAllCerts()
}
