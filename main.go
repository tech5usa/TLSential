package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ImageWare/TLSential/acme"
	"github.com/ImageWare/TLSential/api"
	"github.com/ImageWare/TLSential/certificate"
	"github.com/ImageWare/TLSential/repository/boltdb"
	"github.com/ImageWare/TLSential/service"
	"github.com/ImageWare/TLSential/ui"
	"github.com/gorilla/mux"

	"github.com/boltdb/bolt"
)

// Version is the official version of the server app.
const Version = "v0.0.1"

const localStaticDir = "./static"

type middleware func(http.Handler) http.Handler

func main() {
	fmt.Println("///- Starting up TLSential")
	fmt.Printf("//- Version %s\n", Version)

	var port int
	var dbFile string
	var secretReset bool
	var sessionReset bool
	var tlsCert string
	var tlsKey string
	var noHTTPS bool
	var noHTTPRedirect bool
	var debug bool
	var autoRenewBuffSize int = 10
	var autoRenewListeners int = 10

	// Grab any command line arguments
	flag.IntVar(&port, "port", 443, "port for webserver to run on")
	flag.StringVar(&dbFile, "db", "tlsential.db", "filename for boltdb database")
	flag.BoolVar(&secretReset, "secret-reset", false, "reset the JWT secret - invalidates all API sessions")
	flag.BoolVar(&secretReset, "session-reset", false, "reset the Session secret - invalidates all Web sessions")
	flag.StringVar(&tlsCert, "tls-cert", "/etc/pki/tlsential.crt", "file path for tls certificate")
	flag.StringVar(&tlsKey, "tls-key", "/etc/pki/tlsential.key", "file path for tls private key")
	flag.BoolVar(&noHTTPS, "no-https", false, "flag to run over http (HIGHLY INSECURE)")
	flag.BoolVar(&noHTTPRedirect, "no-http-redirect", false, "flag to not redirect HTTP requests to HTTPS")
	flag.BoolVar(&debug, "debug", false, "flag to increase logging")
	flag.IntVar(&autoRenewBuffSize, "renew-buff", 10, "Set the buffer size of the certificate renewal channel")
	flag.IntVar(&autoRenewListeners, "renew-threads", 10, "Set the number of threads handling certificate renewals and issues")

	flag.Parse()

	if autoRenewBuffSize < 1 || autoRenewBuffSize > 100 {
		log.Fatal("renew-buff out of range. Must be between 1 and 100")
	}

	if autoRenewListeners < 1 || autoRenewListeners > 100 {
		log.Fatal("renew-threads out of range. Must be between 1 and 100")
	}

	// Open our database file.
	db, err := bolt.Open(dbFile, 0666, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Print("Bolt DB file lock timeout")
		log.Fatal(err)
	}
	defer db.Close()

	if secretReset {
		resetSecret(db)
	}
	initSecret(db)

	if sessionReset {
		resetSessionKey(db)
	}

	// Start a goroutine to automatically renew certificates in the DB.
	cs := newCertService(db)
	as := newACMEService(db)

	service.CreateChannelsAndListeners(autoRenewBuffSize, autoRenewListeners, cs, as)

	// Run http server concurrently
	// Load routes for the server
	var mux http.Handler

	// Pass bool for HTTPS as it specifically needs to be disabled in CSRF
	// protection if no HTTPS.
	mux = NewMux(noHTTPS, db)

	if debug {
		//For now the only middleware that debug adds is basic request logging.
		//But there may be more we want to chain in the future.
		mux = chainMiddleware(mux, requestLoggingMiddleWare)
	}

	// Thanks Filippo
	tlsConfig := &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8+ only
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8+ only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8+ only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	s := http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      chainMiddleware(mux, removeTrailingSlash),
		TLSConfig:    tlsConfig,
	}

	if noHTTPS {
		fmt.Println("*** WARNING ***")
		fmt.Println("* It is extremely unsafe to use this app without proper HTTPS *")
		log.Fatal(s.ListenAndServe())
	} else {

		//Create an HTTP server that exists solely to redirect to https
		httpSrv := http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  5 * time.Second,
			Handler: chainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Connection", "close")
				url := "https://" + req.Host + req.URL.String()
				http.Redirect(w, req, url, http.StatusMovedPermanently)
			}), removeTrailingSlash),
		}

		if !noHTTPRedirect {
			go func() { log.Fatal(httpSrv.ListenAndServe()) }()
		}

		log.Fatal(s.ListenAndServeTLS(tlsCert, tlsKey))
	}

}

func chainMiddleware(handler http.Handler, middlewares ...middleware) http.Handler {
	for _, m := range middlewares {
		handler = m(handler)
	}
	return handler
}

func getIP(r *http.Request) string {
	addr := r.Header.Get("X-FORWARDED-FOR")
	if addr == "" {
		addr = r.RemoteAddr
	}
	return addr
}

func requestLoggingMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		//Defer in case one of the handlers down the line calls panic
		defer func() {
			log.Println(getIP(r), r.Method, r.URL.Path, time.Since(start))
		}()

		next.ServeHTTP(w, r)
	})
}

// removeTrailingSlash removes any final / off the end of routes, otherwise
// gorilla mux treats url/ and url differently which is unneeded in this app.
func removeTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}
		next.ServeHTTP(w, r)
	})
}

// NewMux returns a new http.ServeMux with established routes.
func NewMux(unsafe bool, db *bolt.DB) *http.ServeMux {
	apiHandler := newAPIHandler(db)
	uiHandler := newUIHandler(db)

	s := http.NewServeMux()
	s.Handle("/ui/", uiHandler.Route(unsafe))

	s.Handle("/api/", apiHandler.Route())

	r := mux.NewRouter()
	// TODO: Make sure this mostly always works no matter what working directory
	// is.
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(localStaticDir))))
	s.Handle("/static/", r)

	s.Handle("/", http.RedirectHandler("/ui/dashboard", http.StatusMovedPermanently))

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

func initSessionKey(db *bolt.DB) {
	crepo, err := boltdb.NewConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	s, err := crepo.SessionKey()
	if err != nil {
		log.Fatal(err)
	}
	if len(s) < 32 {
		c := 32
		b := make([]byte, c)
		_, err := rand.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		crepo.SetSessionKey(b)
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

func resetSessionKey(db *bolt.DB) {
	crepo, err := boltdb.NewConfigRepository(db)
	if err != nil {
		log.Fatal(err)
	}

	err = crepo.SetSessionKey(nil)
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

// newUIHandler takes a bolt.DB and builds all necessary repos and usescases
// for this app.
func newUIHandler(db *bolt.DB) ui.Handler {
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

	return ui.NewHandler(Version, us, cs, chs, crs, as)
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
