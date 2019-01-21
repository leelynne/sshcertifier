package client

import (
	"bytes"
	"context"
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

type OauthClientSetup int

const (
	OauthClientLocalServer OauthClientSetup = iota
)

type CertClient struct {
	oauthType    OauthClientSetup
	certifierURL string
	hclient      *http.Client
	localServ    *http.Server
	certPrefix   string
	logger       *log.Logger
}

func New(certifierURL string, verifyCert bool, certPrefix string, logger *log.Logger) (*CertClient, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !verifyCert,
			},
		},
	}

	if certPrefix == "" {
		certPrefix = "sshcertifier"
	}
	return &CertClient{
		certifierURL: certifierURL,
		hclient:      client,
		certPrefix:   certPrefix,
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

func (cc *CertClient) Auth() (code string, e error) {
	resp, err := cc.hclient.Post(fmt.Sprintf("%s/oauth/init", cc.certifierURL), "", nil)
	if err != nil {
		return "", errors.Wrapf(err, "Error calling oauth/init")
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "Error reading response from oauth/init")
	}

	oresp := api.OAuthInitResponse{}
	err = json.Unmarshal(respBytes, &oresp)
	if err != nil {
		return "", errors.Wrapf(err, "Error parsing oauth resp")
	}
	code, err = cc.waitForAuthCode(oresp.OAuthURL)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (cc *CertClient) CertifyUser(cu *CertUser, code string) error {
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
	req.Header.Set("Authorization", code)
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
	cc.logger.Printf("Writing certificate to '%s'", cu.certPath)
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

func (cc *CertClient) waitForAuthCode(oauthURL string) (code string, e error) {
	codechan := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cc.logger.Printf("uri: '%s'", r.RequestURI)
		cc.logger.Printf("URL: '%s'", r.URL)
		code := r.URL.Query()["code"][0]
		codechan <- code
	})
	localServer := &http.Server{
		Addr:    ":443",
		Handler: mux,
	}

	go func() {
		cc.logger.Print("Opening local server")
		err := localServer.ListenAndServe()
		cc.logger.Print("Local server done - %s", err.Error())
	}()

	defer localServer.Shutdown(context.Background())

	cc.logger.Printf("Opening '%s'", oauthURL)
	err := open.Run(string(oauthURL))
	if err != nil {
		return "", errors.Wrapf(err, "Error opening browser for url '%s'", oauthURL)
	}

	timeout := time.After(10 * time.Second)
	select {
	case code := <-codechan:
		cc.logger.Printf("CODE: '%s'", code)
		return code, nil
	case <-timeout:
		cc.logger.Println("Timeout. Enter code manually:")
		var codeIn string
		fmt.Scanf("%s\n", &codeIn)
		return codeIn, nil
		//return "", errors.New("Did not receive auth code in time.")
	}
}
