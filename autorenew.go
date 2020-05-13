package main

import (
	"log"
	"time"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/certificate"
)

// How often to scan all certificates to determine if they'll need renewal.
var scanPeriod = time.Hour

func scanAllCerts(cs certificate.Service, as acme.Service) {
	now := time.Now()

	certs, err := cs.AllCerts()
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range certs {
		hoursLeft := c.Expiry.Sub(now).Hours()
		daysLeft := int(hoursLeft / 24)
		if daysLeft < c.RenewAt {
			as.GetAutoRenewChannel() <- c.ID
		}
	}
}

func autoRenewal(cs certificate.Service, as acme.Service) {
	for {
		select {
		case <-time.After(scanPeriod):
			log.Print("Scanning all certs for renewal...")
			scanAllCerts(cs, as)
			break
		}
	}
}
