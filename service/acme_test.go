package service

import (
	"testing"

	"github.com/ImageWare/TLSential/model"
)

type certTest struct {
	testName      string
	domains       []string
	email         string
	expectedError string
}

func TestRegister(t *testing.T) {
	certTests := []certTest{
		{
			"happy path",
			[]string{"example.com", "example2.com"},
			"test@notexample.com",
			"",
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
	}

	for _, ct := range certTests {
		t.Run(ct.testName, func(t *testing.T) {

			c, err := model.NewCertificate(ct.domains, ct.email)

			if err != nil {
				t.Error("Error creating certificate", err)
				return
			}
			a := NewAcmeService(nil, nil)
			reg, err := a.Register(c)

			if err != nil {
				c.ACMERegistration = reg
			}

			if err == nil {
				if ct.expectedError != "" {
					t.Error("no error returned when expected")
					return
				}
			}

			if err != nil {
				if err.Error() != ct.expectedError {
					t.Errorf("error mismatch: got %s, expected %s\n", err.Error(), ct.expectedError)
				}
				return
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
