package client

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type CertUser struct {
	osUser         *user.User
	sshDir         string
	pubkeyPath     string
	privatekeyPath string
	certPath       string
	logger         *log.Logger
}

func (cu *CertUser) GetPubkey() (pubkey []byte, err error) {
	createKeypair := false
	if _, err := os.Stat(cu.pubkeyPath); os.IsNotExist(err) {
		createKeypair = true
	}
	if _, err := os.Stat(cu.privatekeyPath); os.IsNotExist(err) {
		createKeypair = true
	}

	if createKeypair {
		cu.logger.Println("Generating new key pair")
		var privatekey []byte
		pubkey, privatekey, err = makeSSHKeyPair(cu.getComment())
		if err != nil {
			return nil, errors.Wrapf(err, "Couldn't generate new ssh keypair")
		}
		err = writeKeyPair(cu.pubkeyPath, pubkey, cu.privatekeyPath, privatekey)
		if err != nil {
			return nil, errors.Wrapf(err, "Couldn't write keypair to disk")
		}
	} else {
		pubkey, err = ioutil.ReadFile(cu.pubkeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "Couldn't read public key file")
		}
	}

	return pubkey, nil
}

func (cu *CertUser) GetPrivateKey() (*ecdsa.PrivateKey, error) {
	pkBytes, err := ioutil.ReadFile(cu.privatekeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not read private key - '%s'", cu.privatekeyPath)
	}

	blk, _ := pem.Decode(pkBytes)
	pk, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not parse private key - '%s'", cu.privatekeyPath)
	}
	return pk, nil
}

func (cu *CertUser) AddToAgent(cert *ssh.Certificate, comment string) error {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	sock, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return errors.Wrapf(err, "Not adding ssh key to ssh agent:Couldn't connect to ssh agent socket at '%s'", sshAuthSock)
	}
	ag := agent.NewClient(sock)

	expiration := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := time.Until(expiration).Seconds()
	// Need to install both the cert and the corresponding private key that was signed
	pk, err := cu.GetPrivateKey()
	if err != nil {
		return err
	}
	certInfo := agent.AddedKey{
		PrivateKey:   pk,
		Certificate:  cert,
		Comment:      comment,
		LifetimeSecs: uint32(lifetime),
	}

	cu.logger.Printf("Adding cert to agent at '%s'", sshAuthSock)
	if err := ag.Add(certInfo); err != nil {
		return errors.Wrap(err, "Not adding ssh key to ssh agent")
	}

	pkInfo := agent.AddedKey{
		PrivateKey: pk,
		Comment:    comment,
	}
	if err := ag.Add(pkInfo); err != nil {
		return errors.Wrap(err, "Not adding ssh key to ssh agent")
	}
	return nil
}

func (cu *CertUser) getComment() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown_host"
	}
	return fmt.Sprintf("%s@%s", cu.osUser.Username, hostname)
}
