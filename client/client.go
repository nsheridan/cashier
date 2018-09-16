package client

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/nsheridan/cashier/lib"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	errNeedsReason = errors.New("reason required")
)

// SavePublicFiles installs the public part of the cert and key.
func SavePublicFiles(prefix string, cert *ssh.Certificate, pub ssh.PublicKey) error {
	if prefix == "" {
		return nil
	}
	pubTxt := ssh.MarshalAuthorizedKey(pub)
	certPubTxt := []byte(cert.Type() + " " + base64.StdEncoding.EncodeToString(cert.Marshal()))

	_prefix := prefix + "/id_" + cert.KeyId

	if err := ioutil.WriteFile(_prefix+".pub", pubTxt, 0644); err != nil {
		return err
	}
	err := ioutil.WriteFile(_prefix+"-cert.pub", certPubTxt, 0644)

	return err
}

// SavePrivateFiles installs the private part of the key.
func SavePrivateFiles(prefix string, cert *ssh.Certificate, key Key) error {
	if prefix == "" {
		return nil
	}
	_prefix := prefix + "/id_" + cert.KeyId
	pemBlock, err := pemBlockForKey(key)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_prefix, pem.EncodeToMemory(pemBlock), 0600)
	return err
}

// InstallCert adds the private key and signed certificate to the ssh agent.
func InstallCert(a agent.Agent, cert *ssh.Certificate, key Key) error {
	t := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := t.Sub(time.Now()).Seconds()
	comment := fmt.Sprintf("%s [Expires %s]", cert.KeyId, t)
	pubcert := agent.AddedKey{
		PrivateKey:   key,
		Certificate:  cert,
		Comment:      comment,
		LifetimeSecs: uint32(lifetime),
	}
	if err := a.Add(pubcert); err != nil {
		return errors.Wrap(err, "unable to add cert to ssh agent")
	}
	privkey := agent.AddedKey{
		PrivateKey:   key,
		Comment:      comment,
		LifetimeSecs: uint32(lifetime),
	}
	if err := a.Add(privkey); err != nil {
		return errors.Wrap(err, "unable to add private key to ssh agent")
	}
	return nil
}

// send the signing request to the CA.
func send(sr *lib.SignRequest, token, ca string, ValidateTLSCertificate bool) (*lib.SignResponse, error) {
	s, err := json.Marshal(sr)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create sign request")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !ValidateTLSCertificate},
		},
		Timeout: 30 * time.Second,
	}
	u, err := url.Parse(ca)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse CA url")
	}
	u.Path = path.Join(u.Path, "/sign")
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(s))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	signResponse := &lib.SignResponse{}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden && strings.HasPrefix(resp.Header.Get("X-Need-Reason"), "required") {
			return signResponse, errNeedsReason
		}
		return signResponse, fmt.Errorf("bad response from server: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(signResponse); err != nil {
		return nil, errors.Wrap(err, "unable to decode server response")
	}
	return signResponse, nil
}

func promptForReason() (message string) {
	fmt.Print("Enter message: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		message = scanner.Text()
	}
	return message
}

// Sign sends the public key to the CA to be signed.
func Sign(pub ssh.PublicKey, token string, conf *Config) (*ssh.Certificate, error) {
	var err error
	validity, err := time.ParseDuration(conf.Validity)
	if err != nil {
		return nil, err
	}
	s := &lib.SignRequest{
		Key:        string(lib.GetPublicKey(pub)),
		ValidUntil: time.Now().Add(validity),
		Version:    lib.Version,
	}
	resp := &lib.SignResponse{}
	for {
		resp, err = send(s, token, conf.CA, conf.ValidateTLSCertificate)
		if err == nil {
			break
		}
		if err != nil && err == errNeedsReason {
			s.Message = promptForReason()
			continue
		} else if err != nil {
			return nil, errors.Wrap(err, "error sending request to CA")
		}
	}
	if resp.Status != "ok" {
		return nil, fmt.Errorf("bad response from CA: %s", resp.Response)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Response))
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse response")
	}
	cert, ok := k.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("did not receive a valid certificate from server")
	}
	return cert, nil
}

// Listener type contains information for the client listener.
type Listener struct {
	Srv       *http.Server
	TargetURL string
	Token     chan string
}

// StartHTTPServer starts an http server in the background.
func StartHTTPServer() *Listener {
	listening := make(chan bool)
	listener := &Listener{
		Srv:   &http.Server{},
		Token: make(chan string),
	}
	timeout := 5 * time.Second          // TODO: Configurable?
	portStart := 8050                   // TODO: Configurable?
	portCheck := []byte("OK")           // TODO: Random?
	authCallbackURL := "/auth/callback" // TODO: Random?
	portCheckURL := "/port/check"       // TODO: Random?

	http.HandleFunc(authCallbackURL,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<html><head><title>Authorized</title></head><body>Authorized. You can now close this window.</body></html>"))
			defer r.Body.Close()
			listener.Token <- r.FormValue("token")
		})

	http.HandleFunc(portCheckURL,
		func(w http.ResponseWriter, r *http.Request) {
			listening <- true
			w.Write(portCheck)
		})

	// Create the http server.
	go func() {
		for port := portStart; port < 65535; port++ {
			listener.Srv.Addr = fmt.Sprintf("localhost:%d", port)
			if err := listener.Srv.ListenAndServe(); err != nil {
				if strings.Contains(err.Error(), "Server closed") {
					return // Shutdown was called.
				} else if !strings.Contains(err.Error(), "address already in use") {
					fmt.Printf("Httpserver: ListenAndServe() error: %s", err)
					return // Some other error.
				}
			}
		}
	}()

	// Make sure http server is up.
	go func() {
		for i := 0 * time.Second; i < timeout; i += time.Second {
			time.Sleep(1)
			resp, err := http.Get(
				fmt.Sprintf("http://%s%s", listener.Srv.Addr, portCheckURL))
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if bytes.Equal(body, portCheck) {
				return
			}
		}
	}()

	select {
	case <-listening:
		listener.TargetURL =
			fmt.Sprintf("http://%s%s", listener.Srv.Addr, authCallbackURL)
		return listener
	case <-time.After(timeout):
		return nil
	}
}
