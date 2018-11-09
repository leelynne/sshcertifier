package client

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"

	"github.com/pkg/errors"
)

type CertUser struct {
	osUser         *user.User
	sshDir         string
	pubkeyPath     string
	privatekeyPath string
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

func (cu *CertUser) getComment() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown_host"
	}
	return fmt.Sprintf("%s@%s", cu.osUser.Username, hostname)
}
