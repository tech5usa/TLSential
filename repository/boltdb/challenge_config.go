package boltdb

import (
	"crypto"
	"fmt"

	"github.com/ImageWare/TLSential/challenge_config"
	"github.com/boltdb/bolt"
)

const (
	challengeConfigBucket = "challenge_config"

	authEmailKey   = "authemail"
	authKeyKey     = "authkey"
	leUserEmailKey = "leemail"
	leUserKeyKey   = "lekey"
)

var challengeConfigBuckets = []string{
	challengeConfigBucket,
}

type challengeConfigRepository struct {
	*bolt.DB
}

// NewChallengeConfigRepository provides a new challenge_config.Repository powered by BoltDB.
func NewChallengeConfigRepository(db *bolt.DB) (challenge_config.Repository, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range challengeConfigBuckets {
			_, err := tx.CreateBucketIfNotExists([]byte(b))
			if err != nil {
				return fmt.Errorf("create bucket: %s", err)
			}
		}
		return nil
	})
	return &challengeConfigRepository{db}, err
}

// AuthEmail returns the currently stored AuthEmail from boltdb.
func (r *challengeConfigRepository) AuthEmail() (string, error) {
	var email string
	err := r.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		v := b.Get([]byte(authEmailKey))
		if v != nil {
			email = string(v)
		}

		return nil
	})
	return email, err
}

// SetAuthEmail stores the given email in boltdb.
func (r *challengeConfigRepository) SetAuthEmail(email string) error {
	err := r.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		b.Put([]byte(authEmailKey), []byte(email))
		return nil
	})
	return err
}

// AuthKey returns the currently stored auth key from boltdb.
func (r *challengeConfigRepository) AuthKey() (string, error) {
	var authkey string
	err := r.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		v := b.Get([]byte(authKeyKey))
		if v == nil {
			return nil
		}
		authkey = string(v)
		return nil
	})
	return authkey, err
}

// SetAuthKey stores the given key in boltdb.
func (r *challengeConfigRepository) SetAuthKey(authkey string) error {
	err := r.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		b.Put([]byte(authKeyKey), []byte(authkey))
		return nil
	})
	return err
}

// AuthKey returns the currently stored auth key from boltdb.
func (r *challengeConfigRepository) LEUserEmail() (string, error) {
	var email string
	err := r.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		v := b.Get([]byte(leUserEmailKey))
		if v == nil {
			return nil
		}
		email = string(v)
		return nil
	})
	return email, err
}

// SetAuthKey stores the given key in boltdb.
func (r *challengeConfigRepository) SetLEUserEmail(email string) error {
	err := r.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		b.Put([]byte(leUserEmailKey), []byte(email))
		return nil
	})
	return err
}

// AuthKey returns the currently stored auth key from boltdb.
func (r *challengeConfigRepository) LEUserKey() (crypto.PrivateKey, error) {
	var key []byte
	err := r.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		v := b.Get([]byte(leUserKeyKey))
		if v == nil {
			return nil
		}
		key = make([]byte, len(v))
		copy(key, v)
		return nil
	})
	return key, err
}

// SetAuthKey stores the given key in boltdb.
func (r *challengeConfigRepository) SetLEUserKey(key crypto.PrivateKey) error {
	err := r.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(challengeConfigBucket))
		b.Put([]byte(leUserKeyKey), []byte(key))
		return nil
	})
	return err
}
