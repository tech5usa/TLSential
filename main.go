package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/api"
	"github.com/ImageWare/TLSential/repository/boltdb"
	"github.com/ImageWare/TLSential/service"

	"github.com/boltdb/bolt"
)

// Version is the official version of the server app.
const Version = "v0.0.1"

func main() {
	fmt.Println("///- Starting up TLSential")
	fmt.Printf("//- Version %s\n", Version)

	var port int
	var dbFile string
	var secretReset bool

	// Grab any command line arguments
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

	ah := newAPIHandler(db)

	// Run http server concurrently
	// Load routes for the server
	// TODO: Refactor api to be under an http/ module to allow for non-api type calls.
	mux := ah.NewMux()

	s := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	log.Fatal(s.ListenAndServe())

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

	return api.NewHandler(Version, us, cs, chs, crs)
}
