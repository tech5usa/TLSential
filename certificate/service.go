package certificate

import (
	"errors"

	"github.com/ImageWare/TLSential/model"
)

var (
	// ErrCertNotFound means the cert id was not found in the repo
	ErrCertNotFound = errors.New("cert not found")

	// ErrCertExists is returned if a create is called on an existing cert
	ErrCertExists = errors.New("cert with that id exists")
)

// Service provides an interface for all business operations on the Cert model.
type Service interface {
	AllCerts() ([]*model.Certificate, error)
	Cert(id string) (*model.Certificate, error)
	SaveCert(c *model.Certificate) error
	DeleteCert(id string) error
	DeleteAllCerts() error
}

// TODO: Add function to reset/refresh Certificate secret in case of
// breach/leak.
