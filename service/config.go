package service

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/config"
	"github.com/ImageWare/TLSential/model"
)

// randBytes is the number of bytes of entropy for SA password
const randBytes = 32

type configService struct {
	repo config.Repository
}

// NewConfigService returns a new instance of a configService initialized with the
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

// CreateSuperAdmin will take a username, generate a new password, and save this
// user with SuperAdmin permissions.
func (s *configService) CreateSuperAdmin(name string) (*model.User, error) {
	p, err := newPassword()
	if err != nil {
		return nil, err
	}

	u, err := model.NewUser(name, p, auth.RoleSuperAdmin)
	if err != nil {
		return nil, err
	}

	err = s.repo.SetSuperAdmin(name)
	return u, err
}

// ResetSuperAdmin will delete the currently stored username for Super Admin,
// which allows a new Super Admin to be initialized.
func (s *configService) ResetSuperAdmin() error {
	return s.repo.SetSuperAdmin("")
}

// newPassword generates 32 cryptographically secure random bytes, base64
// encodes it, and returns it. 256 bits of entropy.
func newPassword() (string, error) {
	c := randBytes
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	pass := base64.StdEncoding.EncodeToString(b)
	return pass, nil
}
