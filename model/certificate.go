package model

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"net/mail"
	"net/url"
	"time"

	"golang.org/x/net/idna"

	"github.com/ImageWare/TLSential/auth"
	"github.com/go-acme/lego/v3/registration"
	"github.com/segmentio/ksuid"
)

const CADirURL = "https://acme-v02.api.letsencrypt.org/directory"

// DefaultRenewAt is the number of days before expiration a cert should be
// renewed at.
const DefaultRenewAt = 30

var ErrInvalidDomains = errors.New("invalid domains")
var ErrInvalidEmail = errors.New("email required")

type Certificate struct {
	ID     string
	Secret string

	// Domains is a list of domains valid for this domain.
	Domains []string
	// Main domain for "Common Name" field of cert.
	CommonName string

	// Let's Encrypt CertURL
	CertURL string
	// Let's Encrypt StableCertURL
	CertStableURL string

	PrivateKey        []byte
	Certificate       []byte
	IssuerCertificate []byte

	// Has this cert been issued yet?
	Issued bool

	// NotAfter
	Expiry time.Time

	// RewnewAt specifies the number of days before expiration a cert should be
	// renewed by.
	RenewAt int

	// TODO: Add renewal time.Duration

	// TODO: Add DNS Configuration foreign key when we allow for more than one
	// DNS Configuration object

	LastError error

	ModTime time.Time

	ACMEEmail        string
	ACMERegistration *registration.Resource
	ACMEKey          *ecdsa.PrivateKey
}

// NewCertificate sets up everything needed for Lego to move forward with cert
// issuance and renewal, as well as generating a unique ID, and a
// cryptographically secure secret.
func NewCertificate(domains []string, email string) (*Certificate, error) {
	id := ksuid.New().String()
	secret := auth.NewPassword()

	if len(domains) == 0 {
		return nil, ErrInvalidDomains
	}

	// Validate domains in list
	if !ValidDomains(domains) {
		return nil, ErrInvalidDomains
	}

	common := domains[0]

	e, err := mail.ParseAddress(email)
	if err != nil {
		return nil, ErrInvalidEmail
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	c := &Certificate{
		ID:         id,
		Secret:     secret,
		Domains:    domains,
		CommonName: common,
		RenewAt:    DefaultRenewAt,
		ACMEEmail:  e.Address,
		ACMEKey:    privateKey,
	}

	return c, nil
}

// GetEmail is needed to implement the User interface for Lego Clients.
func (c *Certificate) GetEmail() string {
	return c.ACMEEmail
}

// GetRegistration is needed to implement the User interface for Lego Clients.
func (c *Certificate) GetRegistration() *registration.Resource {
	return c.ACMERegistration
}

// GetPrivateKey is needed to implement the User interface for Lego Clients.
func (c *Certificate) GetPrivateKey() crypto.PrivateKey {
	return c.ACMEKey
}

// ValidDomains is used to validate that the passed domains set includes only
// valid domains (ie example.com or *.example.com). Returns bool designating
// whether or not they are ALL valid domains.
func ValidDomains(domains []string) bool {

	var domainValidator = idna.New(idna.MapForLookup(), idna.StrictDomainName(false))

	// iterate through each domain and validate it, if any of them fail we fail the
	// function with the appropriate error
	for _, domain := range domains {

		url, _ := url.Parse(domain)

		// schemes are disallowed, this just checks if the domain is a valid URL
		// and if so if it's got a non-empty scheme
		if url != nil && len(url.Scheme) != 0 {
			return false
		}

		_, err := domainValidator.ToASCII(domain)

		if err != nil {
			return false
		}
	}

	return true
}
