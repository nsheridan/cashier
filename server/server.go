package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/csrf"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"go4.org/wkfs"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"

	wkfscache "github.com/nsheridan/autocert-wkfs-cache"
	"github.com/nsheridan/cashier/lib"
	"github.com/nsheridan/cashier/server/auth"
	"github.com/nsheridan/cashier/server/auth/github"
	"github.com/nsheridan/cashier/server/auth/gitlab"
	"github.com/nsheridan/cashier/server/auth/google"
	"github.com/nsheridan/cashier/server/auth/microsoft"
	"github.com/nsheridan/cashier/server/config"
	"github.com/nsheridan/cashier/server/metrics"
	"github.com/nsheridan/cashier/server/signer"
	"github.com/nsheridan/cashier/server/store"
	"github.com/sid77/drop"
)

func loadCerts(certFile, keyFile string) (tls.Certificate, error) {
	key, err := wkfs.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "error reading TLS private key")
	}
	cert, err := wkfs.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "error reading TLS certificate")
	}
	return tls.X509KeyPair(cert, key)
}

// Run the server.
func Run(ctx context.Context, conf *config.Config) *http.Server {
	var err error

	laddr := fmt.Sprintf("%s:%d", conf.Server.Addr, conf.Server.Port)
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(errors.Wrapf(err, "unable to listen on %s:%d", conf.Server.Addr, conf.Server.Port))
	}

	tlsConfig := &tls.Config{}
	if conf.Server.UseTLS {
		if conf.Server.LetsEncryptServername != "" {
			m := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(conf.Server.LetsEncryptServername),
			}
			if conf.Server.LetsEncryptCache != "" {
				m.Cache = wkfscache.Cache(conf.Server.LetsEncryptCache)
			}
			tlsConfig = m.TLSConfig()
		} else {
			if conf.Server.TLSCert == "" || conf.Server.TLSKey == "" {
				log.Fatal("TLS cert or key not specified in config")
			}
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			tlsConfig.Certificates[0], err = loadCerts(conf.Server.TLSCert, conf.Server.TLSKey)
			if err != nil {
				log.Fatal(errors.Wrap(err, "unable to create TLS listener"))
			}
		}
		l = tls.NewListener(l, tlsConfig)
	}

	if conf.Server.User != "" {
		log.Print("Dropping privileges...")
		if err := drop.DropPrivileges(conf.Server.User); err != nil {
			log.Fatal(errors.Wrap(err, "unable to drop privileges"))
		}
	}

	// Unprivileged section
	metrics.Register()

	var authprovider auth.Provider
	switch conf.Auth.Provider {
	case "github":
		authprovider, err = github.New(conf.Auth)
	case "gitlab":
		authprovider, err = gitlab.New(conf.Auth)
	case "google":
		authprovider, err = google.New(conf.Auth)
	case "microsoft":
		authprovider, err = microsoft.New(conf.Auth)
	default:
		log.Fatalf("Unknown provider %s\n", conf.Auth.Provider)
	}
	if err != nil {
		log.Fatal(errors.Wrapf(err, "unable to use provider '%s'", conf.Auth.Provider))
	}

	keysigner, err := signer.New(conf.SSH)
	if err != nil {
		log.Fatal(err)
	}

	certstore, err := store.New(conf.Server.Database)
	if err != nil {
		log.Fatal(err)
	}

	app := &application{
		cookiestore:   sessions.NewCookieStore([]byte(conf.Server.CookieSecret)),
		requireReason: conf.Server.RequireReason,
		keysigner:     keysigner,
		certstore:     certstore,
		authprovider:  authprovider,
		config:        conf.Server,
		router:        mux.NewRouter(),
	}
	app.cookiestore.Options = &sessions.Options{
		MaxAge:   900,
		Path:     "/",
		Secure:   conf.Server.UseTLS,
		HttpOnly: true,
	}

	logfile := os.Stderr
	if conf.Server.HTTPLogFile != "" {
		logfile, err = os.OpenFile(conf.Server.HTTPLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
		if err != nil {
			log.Printf("error opening log: %v. logging to stdout", err)
		}
	}

	app.setupRoutes()
	r := handlers.LoggingHandler(logfile, app.router)
	s := &http.Server{
		Handler:      r,
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server on %s", laddr)
	go s.Serve(l)
	return s
}

// mwVersion is middleware to add a X-Cashier-Version header to the response.
func mwVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cashier-Version", lib.Version)
		next.ServeHTTP(w, r)
	})
}

func encodeString(s string) string {
	var buffer bytes.Buffer
	chunkSize := 70
	runes := []rune(base64.StdEncoding.EncodeToString([]byte(s)))

	for i := 0; i < len(runes); i += chunkSize {
		end := i + chunkSize
		if end > len(runes) {
			end = len(runes)
		}
		buffer.WriteString(string(runes[i:end]))
		buffer.WriteString("\n")
	}
	buffer.WriteString(".\n")
	return buffer.String()
}

//go:embed static
var static embed.FS

// application contains local context - cookiestore, authsession etc.
type application struct {
	cookiestore   *sessions.CookieStore
	authprovider  auth.Provider
	certstore     store.CertStorer
	keysigner     *signer.KeySigner
	router        *mux.Router
	config        *config.Server
	requireReason bool
}

func (a *application) setupRoutes() {
	// login required
	csrfHandler := csrf.Protect([]byte(a.config.CSRFSecret), csrf.Secure(a.config.UseTLS))
	a.router.Methods("GET").Path("/").Handler(a.authed(http.HandlerFunc(a.index)))
	a.router.Methods("POST").Path("/admin/revoke").Handler(a.authed(csrfHandler(http.HandlerFunc(a.revoke))))
	a.router.Methods("GET").Path("/admin/certs").Handler(a.authed(csrfHandler(http.HandlerFunc(a.getAllCerts))))
	a.router.Methods("GET").Path("/admin/certs.json").Handler(a.authed(http.HandlerFunc(a.getCertsJSON)))

	// no login required
	a.router.Methods("GET").Path("/auth/login").HandlerFunc(a.auth)
	a.router.Methods("GET").Path("/auth/callback").HandlerFunc(a.auth)
	a.router.Methods("GET").Path("/revoked").HandlerFunc(a.revoked)
	a.router.Methods("POST").Path("/sign").HandlerFunc(a.sign)

	a.router.Methods("GET").Path("/healthcheck").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok")
	})
	a.router.Methods("GET").Path("/metrics").Handler(promhttp.Handler())

	// static files
	a.router.PathPrefix("/static/").Handler(http.FileServer(http.FS(static)))

	// middlewares
	a.router.Use(mwVersion)
	a.router.Use(handlers.CompressHandler)
	a.router.Use(handlers.RecoveryHandler())
}

func (a *application) getAuthToken(r *http.Request) *oauth2.Token {
	token := &oauth2.Token{}
	marshalled := a.getSessionVariable(r, "token")
	json.Unmarshal([]byte(marshalled), token)
	return token
}

func (a *application) setAuthToken(w http.ResponseWriter, r *http.Request, token *oauth2.Token) {
	v, _ := json.Marshal(token)
	a.setSessionVariable(w, r, "token", string(v))
}

func (a *application) getSessionVariable(r *http.Request, key string) string {
	session, _ := a.cookiestore.Get(r, "session")
	v, ok := session.Values[key].(string)
	if !ok {
		v = ""
	}
	return v
}

func (a *application) setSessionVariable(w http.ResponseWriter, r *http.Request, key, value string) {
	session, _ := a.cookiestore.Get(r, "session")
	session.Values[key] = value
	session.Save(r, w)
}

func (a *application) authed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := a.getAuthToken(r)
		autoToken := r.FormValue("auto_token")
		if !t.Valid() || !a.authprovider.Valid(t) {
			// This is the initial request - set auto_token regardless.
			// This will handle cases where someone had an uto_token port
			// and is not coming in without one.
			a.setSessionVariable(w, r, "auto_token", autoToken)
			a.setSessionVariable(w, r, "origin_url", r.URL.EscapedPath())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		// We're already authed so set it to the new value.
		if autoToken != "" {
			a.setSessionVariable(w, r, "auto_token", autoToken)
		}
		next.ServeHTTP(w, r)
	})
}
