package acme

import "github.com/ImageWare/TLSential/model"

// Trigger an ACME request for the id
type Service interface {
	Trigger(id string)
	Renew(c *model.Certificate)
}
