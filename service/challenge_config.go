package service

import (
	"time"

	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/ImageWare/TLSential/model"
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

	cfConfig.PropagationTimeout = time.Minute * 10

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

func (s *challengeConfigService) Auth() (*model.ChallengeConfig, error) {
	email, err := s.repo.AuthEmail()
	if err != nil {
		return nil, err
	}
	key, err := s.repo.AuthKey()

	return &model.ChallengeConfig{AuthEmail: email, AuthKey: key}, err
}

func (s *challengeConfigService) SetAuth(email, key string) error {
	err := s.repo.SetAuthEmail(email)
	if err != nil {
		return err
	}
	err = s.repo.SetAuthKey(key)
	return err
}
