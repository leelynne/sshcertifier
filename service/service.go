package service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSHCertifier struct {
	caPrivateKey  ssh.Signer
	sshExtensions map[string]string
	hsrv          *http.Server
}

type CertifyRequest struct {
	User       string `json:"user"`
	UserPubKey []byte `json:"user_pub_key"` // in authorized key file format
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

func (sc *SSHCertifier) createCert(user string, pubkeyRaw []byte, principals []string, duration string) (*ssh.Certificate, error) {

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyRaw)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldn't parse pub key '%s'", string(pubkeyRaw))
	}
	// load client certificate request
	cert := &ssh.Certificate{
		Nonce:           []byte{},
		Key:             pubkey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           user,
		ValidBefore:     10,
		ValidAfter:      20,
		ValidPrincipals: principals,
		Permissions: ssh.Permissions{
			Extensions: sc.sshExtensions,
		},
	}

	err = cert.SignCert(rand.Reader, sc.caPrivateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldn't sign cert")
	}

	return cert, nil
}
