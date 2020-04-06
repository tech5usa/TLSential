package model

// ChallengeConfig provides all necessary information for a Cloudflare DNS
// Challenge provider.
type ChallengeConfig struct {
	// AuthEmail is the Cloudflare account email
	AuthEmail string

	// AuthKey is the API key to use to then retrieve a Cloudflare API token.
	AuthKey string
}

func NewChallengeConfig(email, key string) *ChallengeConfig {
	return &ChallengeConfig{email, key}
}
