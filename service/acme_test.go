package service

import (
	"errors"
	"testing"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/model"
	lregistration "github.com/go-acme/lego/v3/registration"
)

type certTest struct {
	testName      string
	domains       []string
	email         string
	registrar     UserRegistrar
	expectedError string
}

type justReturnRegistrar struct {
	resource *lregistration.Resource
	err      error
}

func (r *justReturnRegistrar) Register(u lregistration.User) (*lregistration.Resource, error) {
	return r.resource, r.err
}

func TestRegister(t *testing.T) {
	passThruError := errors.New("This is the expected error")
	certTests := []certTest{
		{
			"happy path",
			[]string{"example.com", "example2.com"},
			"test@notexample.com",
			&justReturnRegistrar{nil, nil},
			"",
		},
		{
			//This test makes sure the registrar is actually being called
			"return error",
			[]string{"somestuff.com"},
			"test@aurl.com",
			&justReturnRegistrar{nil, passThruError},
			passThruError.Error(),
		},
	}

	for _, ct := range certTests {
		t.Run(ct.testName, func(t *testing.T) {

			c, err := model.NewCertificate(ct.domains, ct.email)

			if err != nil {
				t.Error("Error creating certificate", err)
				return
			}
			var a acme.Service
			if ct.registrar == nil {
				a = NewAcmeService(nil, nil)
			} else {
				a = NewAcmeServiceWithRegistrar(nil, nil, ct.registrar)
			}
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

func TestChannels(t *testing.T) {
	t.Run("request_issue", func(t *testing.T) {
		CreateChannelsAndListeners(1, 0, nil, nil)

		a := NewAcmeServiceWithRegistrar(nil, nil, nil)

		if !a.RequestRenew("id") {
			t.Error("Should not have blocked yet")
			return
		}

		if a.RequestIssue("id2") {
			t.Error("Should have blocked")
			return
		}

		select {
		case id := <-a.GetAutoRenewChannel():
			if id != "id" {
				t.Errorf("expected 'id' but got '%s'", id)
			}
			break
		default:
			t.Error("Could not read from channel")
		}
	})

}
