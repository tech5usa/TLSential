package config

import (
	"github.com/ImageWare/TLSential/auth"
)

// Service provides an interface for manipulating configs.
type Service interface {
	JWTSecret() (*auth.JWTSecret, error)
	SuperAdmin() (string, error)
	SetJWTSecret([]byte) error
	SetSuperAdmin(string) error
}
