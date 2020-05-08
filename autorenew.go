package main

import (
	"log"
	"time"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/service"
)

// How often to scan all certificates to determine if they'll need renewal.
var scanPeriod = time.Hour

func autoRenewal(cs certificate.Service, as acme.Service) {
	for {
		// TODO: Have API calls trigger a channel so all renews/issues funnel to
		// here.
		// Selecet not currently needed as there is only one case, but in the
		// future with a channel, we will want the select.
		select {
		case <-time.After(scanPeriod):
			log.Print("Scanning all certs for renewal...")
			now := time.Now()

			certs, err := cs.AllCerts()
			if err != nil {
				log.Fatal(err)
			}
			for _, c := range certs {
				hoursLeft := c.Expiry.Sub(now).Hours()
				daysLeft := int(hoursLeft / 24)
				if daysLeft < c.RenewAt {
					as.Renew(c)
				}
			}

		case id := <-service.CertAutoRenewChan:
			c, err := cs.Cert(id)

			if err != nil {
				log.Printf("main: autoRenewal: error with triggered autorenew of cert '%s': %s", id, err.Error())
				break
			}

			if c == nil {
				log.Printf("main: autoRenewal: told to renew cert '%s' which doesn't exist", id)
				break
			}

			as.Renew(c)

		case id := <-service.CertIssueChan:
			as.Trigger(id)
		}
	}
}
