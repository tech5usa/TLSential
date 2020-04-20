package model

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"time"

	"github.com/ImageWare/TLSential/auth"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/segmentio/ksuid"
)

const CADirURL = "https://acme-v02.api.letsencrypt.org/directory"

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

	// TODO: Add renewal time.Duration

	// TODO: Add DNS Configuration foreign key when we allow for more than one
	// DNS Configuration object

	LastError error

	ACMEEmail        string
	ACMERegistration *registration.Resource
	ACMEKey          *ecdsa.PrivateKey
}

var ErrInvalidDomains = errors.New("invalid domains")
var ErrEmailRequired = errors.New("email required")

func NewCertificate(domains []string, email string) (*Certificate, error) {
	id := ksuid.New().String()
	secret := auth.NewPassword()

	// TODO: Actually parse these to determine if valid domains
	if len(domains) == 0 {
		return nil, ErrInvalidDomains
	}
	common := domains[0]

	// TODO: Parse and determine if valid email address
	if email == "" {
		return nil, ErrEmailRequired
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
		ACMEEmail:  email,
		ACMEKey:    privateKey,
	}

	config := lego.NewConfig(c)

	config.CADirURL = CADirURL
	config.Certificate.KeyType = certcrypto.RSA2048

	// TODO: Determine whether or not to return err or panic.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	c.ACMERegistration = reg

	return c, nil
}

func (c *Certificate) GetEmail() string {
	return c.ACMEEmail
}
func (c *Certificate) GetRegistration() *registration.Resource {
	return c.ACMERegistration
}
func (c *Certificate) GetPrivateKey() crypto.PrivateKey {
	return c.ACMEKey
}
