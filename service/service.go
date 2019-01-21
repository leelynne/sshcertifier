package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	log "github.com/inconshreveable/log15"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

type SSHCertifier struct {
	caPrivateKey  ssh.Signer
	sshExtensions map[string]string
	hsrv          *http.Server
	logger        log.Logger
	hclient       *http.Client
	oauthConfig   *oauth2.Config
	awssess       *session.Session
}

var DefaultSSHExtensions = map[string]string{
	"permit-X11-forwarding":   "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
	"permit-pty":              "",
	"permit-user-rc":          "",
}

func New(region string, caPrivateKey ssh.Signer, sshExtensions map[string]string, oconf *oauth2.Config) (*SSHCertifier, error) {
	if sshExtensions == nil {
		sshExtensions = DefaultSSHExtensions
	}
	sess := session.New(&aws.Config{
		Region: aws.String(region),
	})
	logger := log.New(log.Ctx{"app": "sshcertifier"})
	return &SSHCertifier{
		caPrivateKey:  caPrivateKey,
		sshExtensions: sshExtensions,
		logger:        logger,
		oauthConfig:   oconf,
		awssess:       sess,
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
	sc.logger.Info("Starting sshcertifier2", "port", port)
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
