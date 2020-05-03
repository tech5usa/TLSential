package config

import (
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/model"
)

// Service provides an interface for manipulating configs.
type Service interface {
	JWTSecret() (*auth.JWTSecret, error)
	SuperAdmin() (string, error)
	SetJWTSecret([]byte) error
	CreateSuperAdmin(string) (user *model.User, password string, err error)
	ResetSuperAdmin() error
	SessionKey() ([]byte, error)
	SetSessionKey([]byte) error
}
