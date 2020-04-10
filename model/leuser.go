package model

import (
	"crypto"

	"github.com/go-acme/lego/registration"
)

type LEUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *LEUser) GetEmail() string {
	return u.Email
}
func (u LEUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LEUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}
