package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/api"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/repository/boltdb"
	"github.com/ImageWare/TLSential/service"
	"github.com/ImageWare/TLSential/ui"

	"github.com/boltdb/bolt"
)

// Version is the official version of the server app.
const Version = "v0.0.1"

func main() {
	fmt.Println("///- Starting up TLSential")
	fmt.Printf("//- Version %s\n", Version)

	var email string
	var port int
	var dbFile string
	var secretReset bool

	// Grab any command line arguments
	flag.StringVar(&email, "email", "test@example.com", "Email address for Let's Encrypt account")
	flag.IntVar(&port, "port", 80, "port for webserver to run on")
	flag.StringVar(&dbFile, "database file", "tlsential.db", "filename for boltdb database")
	flag.BoolVar(&secretReset, "secret-reset", false, "reset the JWT secret - invalidates all API sessions")
	flag.Parse()

	// Open our database file.
	db, err := bolt.Open(dbFile, 0666, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if secretReset {
		resetSecret(db)

	}

	initSecret(db)

	// Start a goroutine to automatically renew certificates in the DB.
	cs := newCertService(db)
	as := newACMEService(db)
	go autoRenewal(cs, as)

	// Run http server concurrently
	// Load routes for the server
	mux := NewMux(db)

	s := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: removeTrailingSlash(mux),
	}

	log.Fatal(s.ListenAndServe())
}

func removeTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
			next.ServeHTTP(w, r)
		}
	})
}

// NewMux returns a new http.ServeMux with established routes.
func NewMux(db *bolt.DB) *http.ServeMux {
	apiHandler := newAPIHandler(db)
	cs := newCertService(db)
	uiHandler := ui.NewHandler("TLSential", cs)

	s := http.NewServeMux()
	s.Handle("/", uiHandler.Route())
	s.Handle("/api/", apiHandler.Route())

	return s
}

func initSecret(db *bolt.DB) {
	crepo, err := boltdb.NewConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	s, err := crepo.JWTSecret()
	if err != nil {
		log.Fatal(err)
	}
	if s.ValidSecret() != nil {
		c := 32
		b := make([]byte, c)
		_, err := rand.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		crepo.SetJWTSecret(b)
	}
}

func resetSecret(db *bolt.DB) {
	crepo, err := boltdb.NewConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	err = crepo.SetJWTSecret(nil)
	if err != nil {
		log.Fatal(err)
	}
}

// newAppController takes a bolt.DB and builds all necessary repos and usescases
// for this app.
func newAPIHandler(db *bolt.DB) api.Handler {
	urepo, err := boltdb.NewUserRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	crepo, err := boltdb.NewConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	chrepo, err := boltdb.NewChallengeConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	certrepo, err := boltdb.NewCertificateRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	us := service.NewUserService(urepo)
	cs := service.NewConfigService(crepo, us)
	chs := service.NewChallengeConfigService(chrepo)
	crs := service.NewCertificateService(certrepo)
	as := service.NewAcmeService(crs, chs)

	return api.NewHandler(Version, us, cs, chs, crs, as)
}

// helper for creating an ACME Service from a db.
func newACMEService(db *bolt.DB) acme.Service {
	chrepo, err := boltdb.NewChallengeConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	certrepo, err := boltdb.NewCertificateRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	chs := service.NewChallengeConfigService(chrepo)
	crs := service.NewCertificateService(certrepo)
	as := service.NewAcmeService(crs, chs)

	return as
}

// helper for creating an Certificate Service from a db.
func newCertService(db *bolt.DB) certificate.Service {
	certrepo, err := boltdb.NewCertificateRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	crs := service.NewCertificateService(certrepo)

	return crs
}
