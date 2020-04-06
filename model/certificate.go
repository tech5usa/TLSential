package model

import "time"

type CertificateConfig struct {
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

	Expiry time.Time

	// TODO: Add DNS Configuration foreign key when we allow for more than one
	// DNS Configuration object
}
