package service

import (
	"log"
	"time"

	"github.com/ImageWare/TLSential/acme"
	cert "github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/ImageWare/TLSential/model"
	"github.com/go-acme/lego/v3/certcrypto"
	lcert "github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
)

var CertAutoRenewChan = make(chan string)
var CertIssueChan = make(chan string)

type acmeService struct {
	certService  cert.Service
	challService challenge_config.Service
}

func NewAcmeService(cts cert.Service, chs challenge_config.Service) acme.Service {
	return &acmeService{certService: cts, challService: chs}
}

func (s *acmeService) Trigger(id string) {

	c, err := s.certService.Cert(id)
	if err != nil {
		log.Printf("Error getting cert from ID - ID: %s, Err: %s\n", id, err.Error())
	}

	// Create a user. New accounts need an email and private key to start.

	config := lego.NewConfig(c)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	provider, err := s.challService.NewDNSProvider()
	if err != nil {
		log.Printf("Error creating New DNS Provider - ID: %s, Err: %s\n", id, err.Error())
		c.LastError = err
		return
	}
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		log.Fatal(err)
	}

	request := lcert.ObtainRequest{
		Domains: c.Domains,
		Bundle:  true,
	}

	signedCert, err := client.Certificate.Obtain(request)
	if err != nil {
		c.LastError = err
		log.Printf("Error getting cert from ID - ID: %s, Err: %s\n", id, err.Error())
		err = s.certService.SaveCert(c)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	c.CertURL = signedCert.CertURL
	c.CertStableURL = signedCert.CertStableURL
	c.PrivateKey = signedCert.PrivateKey
	c.Certificate = signedCert.Certificate
	c.IssuerCertificate = signedCert.IssuerCertificate
	c.Issued = true
	c.Expiry = getExpiry(c)

	log.Printf("/- Successfully minted certificate for %s - %s\n", c.ID, c.CommonName)
	err = s.certService.SaveCert(c)
	if err != nil {
		log.Fatal(err)
	}

}

func (s *acmeService) Renew(c *model.Certificate) {
	config := lego.NewConfig(c)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	provider, err := s.challService.NewDNSProvider()
	if err != nil {
		log.Printf("Error creating New DNS Provider - ID: %s, Err: %s\n", c.ID, err.Error())
		c.LastError = err
		return
	}
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		log.Fatal(err)
	}

	pkey, err := certcrypto.ParsePEMPrivateKey(c.PrivateKey)
	if err != nil {
		c.LastError = err
		log.Printf("Error getting privatekey from cert - ID: %s, Err: %s\n", c.ID, err.Error())
		err = s.certService.SaveCert(c)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	request := lcert.ObtainRequest{
		Domains:    c.Domains,
		Bundle:     true,
		PrivateKey: pkey,
	}

	signedCert, err := client.Certificate.Obtain(request)
	if err != nil {
		c.LastError = err
		log.Printf("Error getting cert from ID - ID: %s, Err: %s\n", c.ID, err.Error())
		err = s.certService.SaveCert(c)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	c.CertURL = signedCert.CertURL
	c.CertStableURL = signedCert.CertStableURL
	c.PrivateKey = signedCert.PrivateKey
	c.Certificate = signedCert.Certificate
	c.IssuerCertificate = signedCert.IssuerCertificate
	c.Issued = true
	c.Expiry = getExpiry(c)

	log.Printf("/- Successfully minted certificate for %s - %s\n", c.ID, c.CommonName)
	err = s.certService.SaveCert(c)
	if err != nil {
		log.Fatal(err)
	}

}

func getExpiry(c *model.Certificate) time.Time {
	x509Cert, err := certcrypto.ParsePEMCertificate(c.Certificate)
	if err != nil {
		log.Fatal(err)
	}

	return x509Cert.NotAfter
}
