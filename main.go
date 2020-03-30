package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/api"
	"github.com/ImageWare/TLSential/repository/boltdb"
	"github.com/ImageWare/TLSential/service"

	"github.com/boltdb/bolt"
)

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

// newAppController takes a bolt.DB and builds all necessary repos and usescases
// for this app.
func newAPIHandler(db *bolt.DB) api.APIHandler {
	urepo, err := boltdb.NewUserRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	crepo, err := boltdb.NewConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	us := service.NewUserService(urepo)
	cs := service.NewConfigService(crepo)

	return api.NewAPIHandler(Version, us, cs)
}
