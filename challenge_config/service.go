package challenge_config

import (
	"github.com/ImageWare/TLSential/model"
	"github.com/go-acme/lego/v3/challenge"
)

// Service provides an interface for manipulating configs.
type Service interface {
	NewDNSProvider() (challenge.Provider, error)
	Auth() (*model.ChallengeConfig, error)
	SetAuth(email, key string) error
}
