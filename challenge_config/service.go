package challenge_config

import "github.com/go-acme/lego/v3/challenge"

// Service provides an interface for manipulating configs.
type Service interface {
	NewDNSProvider() (challenge.Provider, error)
}
