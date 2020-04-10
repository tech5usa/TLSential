package challenge_config

// Repository provides an interface for persisting config options.
type Repository interface {
	AuthEmail() (string, error)
	AuthKey() (string, error)
	LEUserEmail() (string, error)
	LEUserKey() ([]byte, error)
	SetAuthEmail(string) error
	SetAuthKey(string) error
	SetLEUserEmail(string) error
	SetLEUserKey([]byte) error
}
