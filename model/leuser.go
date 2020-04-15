package model

import (
	"crypto"
	"crypto/ecdsa"

	"github.com/go-acme/lego/registration"
)

type LEUser struct {
	Email        string
	Registration *registration.Resource
	Key          *ecdsa.PrivateKey
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
