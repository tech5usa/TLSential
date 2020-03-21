package auth

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var MinBytes = 32                   // Minimum amount of bytes for secret allowed.
var ExpiryDuration = 24 * time.Hour // Expire all tokens 24 hours after minting.

var ErrSecretTooShort = errors.New("Secret length must be at least 32 bytes")
var ErrInvalidToken = errors.New("Invalid JWT")

type JWTSecret struct {
	secret []byte
}

// Sign takes a role string to be stored in the JWT and signed.
// WARNING: This method is dangerous to call with a cryptographically
// insecure secret.
func (s *JWTSecret) Sign(role string) (string, error) {
	// Sanity check that secret is not empty and reasonable length
	if len(s.secret) < MinBytes {
		return "", ErrSecretTooShort
	}

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": role,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(ExpiryDuration).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *JWTSecret) Validate(tokenString string) (jwt.MapClaims, error) {
	// Parse takes the token string and a function for looking up/returning the
	// key.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your
		// secret, e.g. []byte("my_secret_key")
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid and the claims map properly.
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		err = claims.Valid()
		return claims, err
	}
	return nil, ErrInvalidToken
}

// SetSecret allows for the secret of the signer to be set, but not exposed.
func (s *JWTSecret) SetSecret(secret []byte) {
	buf := make([]byte, len(secret))
	copy(buf, secret)
	s.secret = buf
}
