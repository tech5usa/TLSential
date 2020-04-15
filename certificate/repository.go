package certificate

import (
	"github.com/ImageWare/TLSential/model"
)

// Repository provides an interface for persisting certificates.
type Repository interface {
	AllCerts() ([]*model.Certificate, error)
	Cert(id string) (*model.Certificate, error)
	SaveCert(c *model.Certificate) error
	DeleteCert(id string) error
	DeleteAllCerts() error
}
