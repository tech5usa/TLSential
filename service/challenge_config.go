package service

import (
	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/providers/dns/cloudflare"
)

type challengeConfigService struct {
	repo challenge_config.Repository
}

func NewChallengeConfigService(r challenge_config.Repository) challenge_config.Service {
	return &challengeConfigService{r}
}

func (s *challengeConfigService) NewDNSProvider() (challenge.Provider, error) {
	cfConfig := cloudflare.NewDefaultConfig()

	email, err := s.repo.AuthEmail()
	cfConfig.AuthEmail = email

	if err != nil {
		return nil, err
	}

	key, err := s.repo.AuthKey()
	cfConfig.AuthKey = key
	if err != nil {
		return nil, err
	}

	dnsChallenge, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		return nil, err
	}

	return dnsChallenge, nil
}
