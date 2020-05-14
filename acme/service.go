package acme

import (
	"github.com/ImageWare/TLSential/model"
	lregistration "github.com/go-acme/lego/v3/registration"
)

// Service implements the ability to trigger a new certificate request, or Renew
// a certificate. Renewal presumes a certificate has already been issued.
type Service interface {
	Trigger(id string)
	Renew(c *model.Certificate)
	RequestIssue(id string) bool
	RequestRenew(id string) bool
	GetAutoRenewChannel() chan string
	GetIssueChannel() chan string
	Register(lregistration.User) (*lregistration.Resource, error)
}
