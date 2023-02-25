package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/nsheridan/cashier/lib"
	"github.com/nsheridan/cashier/server/store"
	"github.com/nsheridan/cashier/server/templates"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func (a *application) sign(w http.ResponseWriter, r *http.Request) {
	var t string
	if ah := r.Header.Get("Authorization"); ah != "" {
		if len(ah) > 6 && strings.ToUpper(ah[0:7]) == "BEARER " {
			t = ah[7:]
		}
	}

	token := &oauth2.Token{
		AccessToken: t,
	}
	if !a.authprovider.Valid(token) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, http.StatusText(http.StatusUnauthorized))
		return
	}

	// Sign the pubkey and issue the cert.
	req := &lib.SignRequest{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, http.StatusText(http.StatusBadRequest))
		return
	}

	if a.requireReason && req.Message == "" {
		w.Header().Add("X-Need-Reason", "required")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, http.StatusText(http.StatusForbidden))
		return
	}

	username := a.authprovider.Username(token)
	a.authprovider.Revoke(token) // We don't need this anymore.
	cert, err := a.keysigner.SignUserKey(req, username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error signing key")
		return
	}

	rec := store.MakeRecord(cert)
	rec.Message = req.Message
	if err := a.certstore.SetRecord(rec); err != nil {
		log.Printf("Error recording cert: %v", err)
	}
	if err := json.NewEncoder(w).Encode(&lib.SignResponse{
		Status:   "ok",
		Response: string(lib.GetPublicKey(cert)),
	}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error signing key")
		return
	}
}

func (a *application) auth(w http.ResponseWriter, r *http.Request) {
	switch r.URL.EscapedPath() {
	case "/auth/login":
		buf := make([]byte, 32)
		io.ReadFull(rand.Reader, buf)
		state := hex.EncodeToString(buf)
		a.setSessionVariable(w, r, "state", state)
		http.Redirect(w, r, a.authprovider.StartSession(state), http.StatusFound)
	case "/auth/callback":
		state := a.getSessionVariable(r, "state")
		if r.FormValue("state") != state {
			log.Printf("Not authorized on /auth/callback")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			break
		}
		originURL := a.getSessionVariable(r, "origin_url")
		if originURL == "" {
			originURL = "/"
		}
		code := r.FormValue("code")
		token, err := a.authprovider.Exchange(code)
		if err != nil {
			log.Printf("Error on /auth/callback: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			w.Write([]byte(err.Error()))
			break
		}
		log.Printf("Token found on /auth/callback, redirecting to %s", originURL)
		a.setAuthToken(w, r, token)

		// if we don't check the token here, it gets into an auth loop
		if !a.authprovider.Valid(token) {
			log.Printf("Not authorized")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			break
		}
		http.Redirect(w, r, originURL, http.StatusFound)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (a *application) index(w http.ResponseWriter, r *http.Request) {
	tok := a.getAuthToken(r)
	autoToken := a.getSessionVariable(r, "auto_token")
	if autoToken != "" {
		http.Redirect(w, r,
			fmt.Sprintf("http://localhost:%s/auth/callback?token=%s",
				autoToken, tok.AccessToken), http.StatusSeeOther)
	} else {
		page := struct {
			Token string
		}{tok.AccessToken}
		page.Token = encodeString(page.Token)
		tmpl := template.Must(template.New("token.html").Parse(templates.Token))
		tmpl.Execute(w, page)
	}
}

func (a *application) revoked(w http.ResponseWriter, r *http.Request) {
	revoked, err := a.certstore.GetRevoked()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, errors.Wrap(err, "error retrieving revoked certs").Error())
		return
	}
	rl, err := a.keysigner.GenerateRevocationList(revoked)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, errors.Wrap(err, "unable to generate KRL").Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(rl)
}

func (a *application) getAllCerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	tmpl := template.Must(template.New("certs.html").Parse(templates.Certs))
	tmpl.Execute(w, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
	})
}

func (a *application) getCertsJSON(w http.ResponseWriter, r *http.Request) {
	includeExpired, _ := strconv.ParseBool(r.URL.Query().Get("all"))
	certs, err := a.certstore.List(includeExpired)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, http.StatusText(http.StatusInternalServerError))
		return
	}
	if err := json.NewEncoder(w).Encode(certs); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, http.StatusText(http.StatusInternalServerError))
		return
	}
}

func (a *application) revoke(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if err := a.certstore.Revoke(r.Form["cert_id"]); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to revoke certs"))
	} else {
		http.Redirect(w, r, "/admin/certs", http.StatusSeeOther)
	}
}
