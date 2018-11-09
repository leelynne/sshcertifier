package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSHCertifier struct {
	caPrivateKey  ssh.Signer
	sshExtensions map[string]string
	hsrv          *http.Server
	logger        log.Logger
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
	logger := log.New(log.Ctx{"app": "sshcertifier"})
	return &SSHCertifier{
		caPrivateKey:  caPrivateKey,
		sshExtensions: sshExtensions,
		logger:        logger,
	}, nil
}

func (sc *SSHCertifier) Run(ctx context.Context, port int) error {
	tlsconf, err := getTLSConfig()
	if err != nil {
		return err
	}
	sc.hsrv = &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   sc.getMux(),
		TLSConfig: tlsconf,
	}
	sc.logger.Info("Starting sshcertifier", "port", port)
	return sc.hsrv.ListenAndServeTLS("", "")
}

func (sc *SSHCertifier) Stop(ctx context.Context) {
	sc.hsrv.Shutdown(ctx)
}

func (sc *SSHCertifier) createCert(user string, pubkeyRaw []byte, principals []string, validTime time.Duration) (*ssh.Certificate, error) {

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

	return cert, nil
}
