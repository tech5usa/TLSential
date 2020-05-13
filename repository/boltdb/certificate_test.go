package boltdb

import (
	"testing"

	"github.com/ImageWare/TLSential/model"
	"github.com/boltdb/bolt"
)

func TestCertificate(t *testing.T) {
	db, err := bolt.Open(TestDBPath, 0666, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	r, err := NewCertificateRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	c, err := model.NewCertificate([]string{"foo.com", "bar.com"}, "brady@iwsinc.com")
	if err != nil {
		t.Fatal(err)
	}

	err = r.SaveCert(c)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := r.Cert(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = r.DeleteAllCerts()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c2)
}
