package model

import (
	"crypto/x509"
	"time"
)

type Certificate struct {
	ID string

	// Domains is a list of domains valid for this domain.
	Domains []string
	// Main domain for "Common Name" field of cert.
	CommonName string

	// Let's Encrypt CertURL
	CertURL string
	// Let's Encrypt StableCertURL
	CertStableURL string

	PrivateKey        []byte
	IssuerCertificate []byte

	// NotAfter
	Expiry time.Time

	// TODO: Add renewal time.Duration

	// TODO: Add DNS Configuration foreign key when we allow for more than one
	// DNS Configuration object
}

func (c *Certificate) setExpiry() error {
	cert, err := x509.ParseCertificate(c.IssuerCertificate)
	if err != nil {
		return err
	}
	c.Expiry = cert.NotAfter
	return nil
}
