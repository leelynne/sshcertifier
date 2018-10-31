package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/ssh"
)

type SSHCertifier struct {
}

type CertifyRequest struct {
}

type CA struct {
	pub  *x509.Certificate
	priv *rsa.PrivateKey
}

func (sc *SSHCertifier) HandleCertify(w http.ResponseWriter, r *http.Request) {

}

func crsToCrtExample(user string, pubkeyRaw []byte, principals []string) error {
	pkBytes, err := ioutil.ReadFile("ca")
	if err != nil {
		return err
	}
	pk, err := ssh.ParsePrivateKey(pkBytes)
	if err != nil {
		return err
	}
	pubkey, err := ssh.ParsePublicKey(pubkeyRaw)
	if err != nil {
		return err
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
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-port-forwarding":  "",
				"permit-agent-forwarding": "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	fmt.Printf("%+v\n", cert)
	cert.SignCert(rand.Reader, pk)

	out := cert.Marshal()
	ioutil.WriteFile("cert.pub", out, 0644)
	return nil
}
