package boltdb

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/model"
	"github.com/boltdb/bolt"
	"github.com/go-acme/lego/v3/registration"
)

//Error used internally by Cert(id string). Is not meant to be exposed.
var errCertificateNotFound = errors.New("Certificate not found")

var certBucket = []byte("certs")

var certBuckets = []string{
	string(certBucket),
}

type certRepository struct {
	*bolt.DB
}

// Used as a middleman to encode in json for storage, purely for
// ecdsa.PrivateKey storage.
type encodedCert struct {
	ID     string
	Secret string

	Domains    []string
	CommonName string

	CertURL       string
	CertStableURL string

	PrivateKey        []byte
	Certificate       []byte
	IssuerCertificate []byte

	Issued bool

	Expiry  time.Time
	RenewAt int

	LastError string

	ACMEEmail        string
	ACMERegistration *registration.Resource

	// Encode key so we can store it.
	// TODO: In go1.15, we should see a JSON Marshal for ecdsa.PrivateKeys, and
	// we can drop this whole struct.
	ACMEKey string
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
	var ecerts []*encodedCert
	err := cr.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)

		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			c := &encodedCert{}
			err := json.Unmarshal(v, &c)
			if err != nil {
				return err
			}

			ecerts = append(ecerts, c)
		}

		return nil
	})

	var certs = make([]*model.Certificate, 0)
	for _, ec := range ecerts {
		var lastError error
		if ec.LastError != "" {
			lastError = errors.New(ec.LastError)
		}
		c := &model.Certificate{
			ID:                ec.ID,
			Secret:            ec.Secret,
			Domains:           ec.Domains,
			CommonName:        ec.CommonName,
			CertURL:           ec.CertURL,
			CertStableURL:     ec.CertStableURL,
			PrivateKey:        ec.PrivateKey,
			Certificate:       ec.Certificate,
			IssuerCertificate: ec.IssuerCertificate,
			Issued:            ec.Issued,
			Expiry:            ec.Expiry,
			RenewAt:           ec.RenewAt,
			LastError:         lastError,
			ACMEEmail:         ec.ACMEEmail,
			ACMERegistration:  ec.ACMERegistration,
			ACMEKey:           decode(ec.ACMEKey),
		}
		certs = append(certs, c)
	}
	return certs, err
}

// Cert takes an id and returns their whole cert object.
func (cr *certRepository) Cert(id string) (*model.Certificate, error) {
	ec := &encodedCert{}
	err := cr.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return errCertificateNotFound
		}

		err := json.Unmarshal(v, &ec)
		return err
	})

	if err == errCertificateNotFound {
		return nil, nil
	}

	var lastError error
	if ec.LastError != "" {
		lastError = errors.New(ec.LastError)
	}
	c := &model.Certificate{
		ID:                ec.ID,
		Secret:            ec.Secret,
		Domains:           ec.Domains,
		CommonName:        ec.CommonName,
		CertURL:           ec.CertURL,
		CertStableURL:     ec.CertStableURL,
		PrivateKey:        ec.PrivateKey,
		Certificate:       ec.Certificate,
		IssuerCertificate: ec.IssuerCertificate,
		Issued:            ec.Issued,
		Expiry:            ec.Expiry,
		RenewAt:           ec.RenewAt,
		LastError:         lastError,
		ACMEEmail:         ec.ACMEEmail,
		ACMERegistration:  ec.ACMERegistration,
		ACMEKey:           decode(ec.ACMEKey),
	}
	return c, err
}

// SaveCert persists a Cert in BoltStore.
func (cr *certRepository) SaveCert(c *model.Certificate) error {
	var lastError string
	if c.LastError != nil {
		lastError = c.LastError.Error()
	}
	ec := &encodedCert{
		ID:                c.ID,
		Secret:            c.Secret,
		Domains:           c.Domains,
		CommonName:        c.CommonName,
		CertURL:           c.CertURL,
		CertStableURL:     c.CertStableURL,
		PrivateKey:        c.PrivateKey,
		Certificate:       c.Certificate,
		IssuerCertificate: c.IssuerCertificate,
		Issued:            c.Issued,
		Expiry:            c.Expiry,
		RenewAt:           c.RenewAt,
		LastError:         lastError,
		ACMEEmail:         c.ACMEEmail,
		ACMERegistration:  c.ACMERegistration,
		ACMEKey:           encode(c.ACMEKey),
	}
	err := cr.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(certBucket)
		buf, err := json.Marshal(ec)
		b.Put([]byte(ec.ID), buf)
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

func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func decode(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil
	}
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil
	}
	return privateKey
}
