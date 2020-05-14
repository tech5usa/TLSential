package service

import (
	"testing"
	"time"

	"github.com/ImageWare/TLSential/model"
)

type certTest struct {
	testName      string
	domains       []string
	email         string
	expectedError string
}

func testRegister(t *testing.T) {
	certTests := []certTest{
		{
			"happy path",
			[]string{"example.com", "example2.com"},
			"test@notexample.com",
			"",
		},
		{
			"no domains",
			[]string{},
			"test@notexample.com",
			model.ErrInvalidDomains.Error(),
		},
		{
			"email at example.com",
			[]string{"example.com"},
			"test@example.com",
			"acme: error: 400 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-acct :: urn:ietf:params:acme:error:invalidEmail :: Error creating new account :: invalid contact domain. Contact emails @example.com are forbidden, url: ",
		},
		{
			"wildcard domain",
			[]string{"*.example.com"},
			"test@notexample.com",
			"",
		},
		{
			"bad wildcard domain",
			[]string{"https://*.example.com"},
			"test@notexample.com",
			model.ErrInvalidDomains.Error(),
		},
	}

	for _, ct := range certTests {
		t.Run(ct.testName, func(t *testing.T) {
			c, err := model.NewCertificate(ct.domains, ct.email)

			if err == nil {
				a := NewAcmeService(nil, nil)
				reg, err := a.Register(c)
				if err != nil {
					c.ACMERegistration = reg
				}
			}

			if err == nil {
				if ct.expectedError != "" {
					t.Error("no error returned when expected")
				}
			}

			if err != nil {
				if err.Error() != ct.expectedError {
					t.Errorf("error mismatch: got %s, expected %s\n", err.Error(), ct.expectedError)
				}
				if c != nil {
					t.Error("certificate should be nil on error")
				}
				return
			}

			if c.ID == "" {
				t.Error("certificate ID blank")
			}

			if c.Secret == "" {
				t.Error("certificate Secret blank")
			}

			match := testEq(ct.domains, c.Domains)
			if !match {
				t.Error("given domains and certificate domains mismatch")
			}

			if c.CommonName != ct.domains[0] {
				t.Error("common name is not correct domain")
			}

			if c.CertURL != "" {
				t.Error("cert url should be blank")
			}
			if c.CertStableURL != "" {
				t.Error("cert stable url should be blank")
			}

			if len(c.PrivateKey) != 0 {
				t.Error("private key should be empty")
			}
			if len(c.Certificate) != 0 {
				t.Error("certificate should be empty")
			}
			if len(c.IssuerCertificate) != 0 {
				t.Error("issuer certificate should be empty")
			}

			if c.Issued != false {
				t.Error("issued should be false")
			}

			var blankTime time.Time
			if !c.Expiry.Equal(blankTime) {
				t.Error("expiry shouldn't have been set")
			}

			if c.RenewAt != model.DefaultRenewAt {
				t.Error("renew at not defuault")
			}

			if c.LastError != nil {
				t.Error("last error shouldn't be set")
			}

			if c.ACMEEmail != ct.email {
				t.Error("email mismatch")
			}

			if c.ACMEKey == nil {
				t.Error("acme key should not be nil")
			}
		})
	}
}

func testEq(a, b []string) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
