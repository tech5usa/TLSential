package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"

	"github.com/ImageWare/TLSential/acme"
	cert "github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/go-acme/lego/certcrypto"
	lcert "github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"
)

type acmeService struct {
	certService  cert.Service
	challService challenge_config.Service
}

func NewAcmeService(cts cert.Service, chs challenge_config.Service) acme.Service {
	return &acmeService{certService: cts, challService: chs}
}

func (s *acmeService) Trigger(id string) {

	leuser := s.challService.LEUser()
	if leuser.Key == nil {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		leuser.Key = privateKey
		err = s.challService.SaveLEUser(leuser)
		if err != nil {
			log.Fatal(err)
		}

	}
	// Create a user. New accounts need an email and private key to start.

	config := lego.NewConfig(leuser)

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
	}
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		log.Fatal(err)
	}

	c, err := s.certService.Cert(id)
	if err != nil {
		log.Printf("Error getting cert from ID - ID: %s, Err: %s\n", id, err.Error())
	}

	request := lcert.ObtainRequest{
		Domains: c.Domains,
		Bundle:  true,
	}

	signedCert, err := client.Certificate.Obtain(request)
	if err != nil {
		c.LastError = err
		log.Printf("Error getting cert from ID - ID: %s, Err: %s\n", id, err.Error())
		return
	}
	c.PrivateKey = signedCert.PrivateKey
	c.IssuerCertificate = signedCert.IssuerCertificate
	c.Issued = true
	log.Printf("/- Successfully minted certificate for %s - %s\n", c.ID, c.CommonName)
	err = s.certService.SaveCert(c)
	if err != nil {
		log.Fatal(err)
	}
}
