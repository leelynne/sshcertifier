package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/user"
	"path/filepath"
	"time"

	"github.com/leelynne/sshcertifier/api"
	"github.com/pkg/errors"
)

type CertClient struct {
	certifierURL string
	hclient      *http.Client
	certPrefix   string
	logger       *log.Logger
}

func New(certifierURL string, verifyCert bool, keypairName string, logger *log.Logger) (*CertClient, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: verifyCert,
			},
		},
	}

	if keypairName == "" {
		keypairName = "sshcertifier"
	}
	return &CertClient{
		certifierURL: certifierURL,
		hclient:      client,
		certPrefix:   keypairName,
		logger:       logger,
	}, nil
}

func (cc *CertClient) NewUser() (*CertUser, error) {
	u, err := user.Current()
	if err != nil {
		return nil, errors.Wrapf(err, "Could not get current user.")
	}

	sshDir := filepath.Join(u.HomeDir, ".ssh")
	return &CertUser{
		osUser:         u,
		sshDir:         sshDir,
		pubkeyPath:     filepath.Join(sshDir, fmt.Sprintf("%s_ed25519.pub", cc.certPrefix)),
		privatekeyPath: filepath.Join(sshDir, fmt.Sprintf("%s_ed25519", cc.certPrefix)),
		logger:         cc.logger,
	}, nil
}

func (cc *CertClient) CertifyUser(cu *CertUser) error {
	pubkey, err := cu.GetPubkey()
	if err != nil {
		return err
	}
	req := api.CertifyRequest{
		User:          cu.osUser.Username,
		UserPublicKey: pubkey,
	}
	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal certify user request")
	}
	resp, err := cc.hclient.Post(cc.certifierURL, "application/json", b)
	if err != nil {
		return errors.Wrapf(err, "Failed to call certifier service")
	}
	defer resp.Body.Close()
	cert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "Couldn't read ceritifier service response")
	}
	err = writeSSHCert(cu.sshDir, cert)
	if err != nil {
		return err
	}
	return nil
}
