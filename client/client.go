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
	"golang.org/x/crypto/ssh"
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
				InsecureSkipVerify: !verifyCert,
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
		certPath:       filepath.Join(sshDir, fmt.Sprintf("%s_ed25519-cert.pub", cc.certPrefix)),
		logger:         cc.logger,
	}, nil
}

func (cc *CertClient) CertifyUser(cu *CertUser) error {
	pubkey, err := cu.GetPubkey()
	if err != nil {
		return err
	}
	certReq := api.CertifyRequest{
		User:          cu.osUser.Username,
		UserPublicKey: pubkey,
	}
	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(certReq)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal certify user request")
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/certify/user", cc.certifierURL), b)
	//req.Header.Set("Accept", "application/json")
	if err != nil {
		return errors.Wrapf(err, "Could not create new http request")
	}

	resp, err := cc.hclient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to call certifier service")
	}
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("Failed to call certifier service. Code: '%s' Error: '%s'", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	certBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "Couldn't read ceritifier service response")
	}

	/*certResp := api.CertifyResponse{}
	err = json.Unmarshal(respBytes, &certResp)
	if err != nil {
		return errors.Wrapf(err, "Couldn't unmarshal response")
	}*/
	err = writeSSHCert(cu.certPath, certBytes)
	if err != nil {
		return err
	}
	parsedCert, comment, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	cert, ok := parsedCert.(*ssh.Certificate)
	if !ok {
		return errors.Errorf("Could not parse certifcate out of result")
	}
	return cu.AddToAgent(cert, comment)
}
