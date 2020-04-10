package model

// TODO: Rename to Providers and flesh out with a few more details like which
// kind of DNS provider, an ID, etc.

// ChallengeConfig provides all necessary information for a Cloudflare DNS
// Challenge provider.
type ChallengeConfig struct {
	// AuthEmail is the Cloudflare account email
	AuthEmail string

	// AuthKey is the API key to use to then retrieve a Cloudflare API token.
	AuthKey string

	// TODO: Refactor this out into another model.
	LEUserEmail string
	LEUserKey   []byte
}

func NewChallengeConfig(email, key string) *ChallengeConfig {
	return &ChallengeConfig{email, key}
}
