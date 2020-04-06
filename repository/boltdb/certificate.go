package boltdb

import (
	"encoding/json"
	"fmt"

	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/model"
	"github.com/boltdb/bolt"
)

var certBucket = []byte("certs")

var certBuckets = []string{
	string(certBucket),
}

type certRepository struct {
	*bolt.DB
}

// NewCertificateRepository returns a new repo object with the associate bolt.DB
func NewCertificateRepository(db *bolt.DB) (certificate.Repository, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range certBuckets {
			_, err := tx.CreateBucketIfNotExists([]byte(b))
			if err != nil {
				return fmt.Errorf("create bucket: %s", err)
			}
		}
		return nil
	})
	return &certRepository{db}, err
}

// AllCerts returns a list of all Cert objects stored in the
// db.
func (cr *certRepository) AllCerts() ([]*model.Certificate, error) {
	var certs []*model.Certificate
	err := cr.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)

		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			c := &model.Certificate{}
			err := json.Unmarshal(v, &c)
			if err != nil {
				return err
			}

			certs = append(certs, c)
		}

		return nil
	})
	return certs, err
}

// Cert takes an id and returns their whole cert object.
func (cr *certRepository) Cert(id string) (*model.Certificate, error) {
	var c *model.Certificate
	err := cr.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		c = &model.Certificate{}
		err := json.Unmarshal(v, &c)
		return err
	})
	return c, err
}

// SaveCert persists a Cert in BoltStore.
func (cr *certRepository) SaveCert(c *model.Certificate) error {
	err := cr.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)
		buf, err := json.Marshal(c)
		b.Put([]byte(c.ID), buf)
		return err
	})
	return err
}

// DeleteCert removes any saved Cert object matching the id
func (cr *certRepository) DeleteCert(id string) error {
	err := cr.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)
		b.Delete([]byte(id))
		return nil
	})
	return err
}

// DeleteAllCerts deletes the Bolt bucket holding certs and recreates
// it, essentially deleting all objects.
func (cr *certRepository) DeleteAllCerts() error {
	err := cr.DB.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(certBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucket(certBucket)
		if err != nil {
			return err
		}

		return nil
	})
	return err
}
