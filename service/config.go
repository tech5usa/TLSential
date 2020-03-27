package service

import (
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/config"
)

type configService struct {
	repo config.Repository
}

// NewUserService returns a new instance of a userService initialized with the
// given repository.
func NewConfigService(repo config.Repository) config.Service {
	return &configService{repo}
}

// JWTSecret provides the current JSON Web Token signing secret in use in the config.
func (s *configService) JWTSecret() (*auth.JWTSecret, error) {
	return s.repo.JWTSecret()
}

// SuperAdmin provides the current SuperAdmin account username set in the config.
func (s *configService) SuperAdmin() (string, error) {
	return s.repo.SuperAdmin()
}

// SetJWTSecret will first make sure the provided secret is valid and then set
// it to the config.
func (s *configService) SetJWTSecret(secret []byte) error {
	// TODO: Make sure secret is valid here.
	return s.repo.SetJWTSecret(secret)
}

// SetSuperAdmin will first make sure the provided username is a valid account
// and then assign it as the SuperAdmin role. Only one is allowed to be set at a
// time.
func (s *configService) SetSuperAdmin(name string) error {
	// TODO: Make sure this is a valid user first.
	return s.repo.SetSuperAdmin(name)
}
