package signer

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/nsheridan/cashier/lib"
	"github.com/nsheridan/cashier/server/store"
	"github.com/nsheridan/cashier/testdata"
	"github.com/stripe/krl"

	"golang.org/x/crypto/ssh"
)

var (
	key, _ = ssh.ParsePrivateKey(testdata.Priv)
	signer = &KeySigner{
		ca:          key,
		validity:    12 * time.Hour,
		principals:  []string{"ec2-user"},
		permissions: []string{"permit-pty", "force-command=/bin/ls"},
	}
)

func TestCert(t *testing.T) {
	r := &lib.SignRequest{
		Key:        string(testdata.Pub),
		ValidUntil: time.Now().Add(1 * time.Hour),
		Message:    "hello world",
	}
	cert, err := signer.SignUserKey(r, "gopher1")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), signer.ca.PublicKey().Marshal()) {
		t.Error("Cert signer and server signer don't match")
	}
	var principals []string
	principals = append(principals, "gopher1")
	principals = append(principals, signer.principals...)
	if !reflect.DeepEqual(cert.ValidPrincipals, principals) {
		t.Errorf("Expected %s, got %s", cert.ValidPrincipals, principals)
	}
	k1, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.Key))
	if err != nil {
		t.Errorf("Unable to parse key: %v", err)
	}
	k2 := cert.Key
	if !bytes.Equal(k1.Marshal(), k2.Marshal()) {
		t.Error("Cert key doesn't match public key")
	}
	if cert.ValidBefore != uint64(r.ValidUntil.Unix()) {
		t.Errorf("Invalid validity, expected %d, got %d", r.ValidUntil.Unix(), cert.ValidBefore)
	}
}

func TestRevocationList(t *testing.T) {
	r := &lib.SignRequest{
		Key:        string(testdata.Pub),
		ValidUntil: time.Now().Add(1 * time.Hour),
	}
	cert1, _ := signer.SignUserKey(r, "revoked")
	cert2, _ := signer.SignUserKey(r, "ok")
	var rec []*store.CertRecord
	rec = append(rec, &store.CertRecord{
		KeyID: cert1.KeyId,
	})
	rl, err := signer.GenerateRevocationList(rec)
	if err != nil {
		t.Error(err)
	}
	k, err := krl.ParseKRL(rl)
	if err != nil {
		t.Error(err)
	}
	if !k.IsRevoked(cert1) {
		t.Errorf("expected cert %s to be revoked", cert1.KeyId)
	}
	if k.IsRevoked(cert2) {
		t.Errorf("cert %s should not be revoked", cert2.KeyId)
	}
}

func TestPermissions(t *testing.T) {
	r := &lib.SignRequest{
		Key:        string(testdata.Pub),
		ValidUntil: time.Now().Add(1 * time.Hour),
	}
	cert, err := signer.SignUserKey(r, "gopher1")
	if err != nil {
		t.Error(err)
	}
	want := struct {
		extensions map[string]string
		options    map[string]string
	}{
		extensions: map[string]string{"permit-pty": ""},
		options:    map[string]string{"force-command": "/bin/ls"},
	}
	if !reflect.DeepEqual(cert.Extensions, want.extensions) {
		t.Errorf("Wrong permissions: wanted: %v got :%v", cert.Extensions, want.extensions)
	}
	if !reflect.DeepEqual(cert.CriticalOptions, want.options) {
		t.Errorf("Wrong options: wanted: %v got :%v", cert.CriticalOptions, want.options)
	}
}

func TestValidityOverride(t *testing.T) {
	signer = &KeySigner{
		ca:               key,
		validity:         12 * time.Hour,
		principals:       []string{"ec2-user"},
		permissions:      []string{"permit-pty", "force-command=/bin/ls"},
		validityOverride: true,
	}
	r := &lib.SignRequest{
		Key:        string(testdata.Pub),
		ValidUntil: time.Now().Add(1 * time.Hour),
	}
	cert, err := signer.SignUserKey(r, "gopher1")
	if err != nil {
		t.Error(err)
	}
	if time.Now().Add(2 * time.Hour).After(time.Unix(int64(cert.ValidBefore), 0)) {
		t.Errorf("cert should have had ValidBefore overridden by validityOverride flag: wanted approx: %d, got: %d", time.Now().UTC().Add(signer.validity).Unix(), cert.ValidBefore)
	}
}
