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
	lregistration "github.com/go-acme/lego/v3/registration"
)

var certAutoRenewChan chan string
var certIssueChan chan string

type acmeService struct {
	certService  cert.Service
	challService challenge_config.Service
	registrar    UserRegistrar
}

type UserRegistrar interface {
	Register(u lregistration.User) (*lregistration.Resource, error)
}

type legoRegistrar struct{}

func CreateChannelsAndListeners(buffSize int, listeners int, cs cert.Service, as acme.Service) {
	certAutoRenewChan = make(chan string, buffSize)
	certIssueChan = make(chan string)

	for i := 0; i < listeners; i++ {
		go handleCertChannels(cs, as)
	}
}

func handleCertChannels(cs cert.Service, as acme.Service) {
	for {
		select {
		case id := <-as.GetAutoRenewChannel():
			c, err := cs.Cert(id)

			if err != nil {
				log.Printf("service: acme: handleCertChannels: error with triggered autorenew of cert '%s': %s", id, err.Error())
				break
			}

			if c == nil {
				log.Printf("service: acme: handleCertChannels: told to renew cert '%s' which doesn't exist", id)
				break
			}

			as.Renew(c)
			break

		case id := <-as.GetIssueChannel():
			as.Trigger(id)
			break
		}
	}
}

//Create a new acme.Service with a default LEGO registrar
func NewAcmeService(cts cert.Service, chs challenge_config.Service) acme.Service {
	return NewAcmeServiceWithRegistrar(cts, chs, &legoRegistrar{})
}

//Create a new acme.Service that uses the supplied UserRegistrar. registrar must not be nil
func NewAcmeServiceWithRegistrar(cts cert.Service, chs challenge_config.Service, registrar UserRegistrar) acme.Service {
	return &acmeService{certService: cts, challService: chs, registrar: registrar}
}

//RequestRenew will try to send to the CertAutoRenewChan channel, but won't block if the channel is full.
//Instead of blocking the function will return false to indicate that the send failed and you should try again later.
func (s *acmeService) RequestRenew(id string) bool {
	select {
	case s.GetAutoRenewChannel() <- id:
		return true
	default:
		return false
	}
}

//RequestIssue will try to send to the CertIssueChan channel, but won't block if the channel is full.
//Instead of blocking the function will return false to indicate that the send failed and you should try again later.
func (s *acmeService) RequestIssue(id string) bool {
	select {
	case s.GetIssueChannel() <- id:
		return true
	default:
		return false
	}
}

func (s *acmeService) GetAutoRenewChannel() chan string {
	return certAutoRenewChan
}

func (s *acmeService) GetIssueChannel() chan string {
	return certIssueChan
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

func (s *acmeService) Register(u lregistration.User) (*lregistration.Resource, error) {
	return s.registrar.Register(u)
}

func getExpiry(c *model.Certificate) time.Time {
	x509Cert, err := certcrypto.ParsePEMCertificate(c.Certificate)
	if err != nil {
		log.Fatal(err)
	}

	return x509Cert.NotAfter
}

func (l *legoRegistrar) Register(u lregistration.User) (*lregistration.Resource, error) {
	config := lego.NewConfig(u)

	config.CADirURL = model.CADirURL
	config.Certificate.KeyType = certcrypto.RSA2048

	c, err := lego.NewClient(config)

	if err != nil {
		return nil, err
	}

	reg, err := c.Registration.Register(lregistration.RegisterOptions{TermsOfServiceAgreed: true})
	return reg, err
}
