package acme

import "github.com/ImageWare/TLSential/model"

// Service implements the ability to trigger a new certificate request, or Renew
// a certificate. Renewal presumes a certificate has already been issued.
type Service interface {
	Trigger(id string)
	Renew(c *model.Certificate)
	RequestIssue(id string) bool
	RequestRenew(id string) bool
	GetAutoRenewChannel() chan string
	GetIssueChannel() chan string
}
