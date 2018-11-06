package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSHCertifier struct {
	caPrivateKey  ssh.Signer
	sshExtensions map[string]string
	hsrv          *http.Server
}

var DefaultSSHExtensions = map[string]string{
	"permit-X11-forwarding":   "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
	"permit-pty":              "",
	"permit-user-rc":          "",
}

func New(caPrivateKey ssh.Signer, sshExtensions map[string]string) (*SSHCertifier, error) {
	if sshExtensions == nil {
		sshExtensions = DefaultSSHExtensions
	}
	return &SSHCertifier{
		caPrivateKey:  caPrivateKey,
		sshExtensions: sshExtensions,
	}, nil
}

func (sc *SSHCertifier) Run(ctx context.Context, tlsconf *tls.Config) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", sc.HandleCertify)
	sc.hsrv = &http.Server{
		Addr:      ":8888",
		Handler:   mux,
		TLSConfig: tlsconf,
	}

	sc.hsrv.ListenAndServeTLS("", "")
}

func (sc *SSHCertifier) Stop(ctx context.Context) {
	sc.hsrv.Shutdown(ctx)
}

func (sc *SSHCertifier) createCert(user string, pubkeyRaw []byte, host string, principals []string, validTime time.Duration) ([]byte, error) {

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyRaw)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldn't parse pub key '%s'", string(pubkeyRaw))
	}
	// load client certificate request
	now := time.Now() //uint64(time.Now().UTC().Unix()),
	until := now.Add(validTime)
	cert := &ssh.Certificate{
		Nonce:           []byte{},
		Key:             pubkey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           user,
		ValidAfter:      uint64(now.UTC().Unix()),
		ValidBefore:     uint64(until.UTC().Unix()),
		ValidPrincipals: principals,
		Permissions: ssh.Permissions{
			Extensions: sc.sshExtensions,
		},
	}

	err = cert.SignCert(rand.Reader, sc.caPrivateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldn't sign cert")
	}

	buf := bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("%s ", cert.Type()))
	buf.WriteString(base64.StdEncoding.EncodeToString(cert.Marshal()))
	if host != "" {
		buf.WriteString(fmt.Sprintf(" %s\n", host))
	} else {
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}
