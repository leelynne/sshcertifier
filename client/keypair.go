package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// makeSSHKeyPair creates an ecdsa private and public key pair. The pubkey is in authorized key file format. The private kem is PEM encoded. This outputs are similar to the output of 'ssh-keygen -t ed25519'
func makeSSHKeyPair(comment string) (pubkeyAuthKey, privateKeyPEM []byte, e error) {
	pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not generate ecdsa key")
	}

	pkBytesRaw, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not marshal ecsda key")
	}

	pkBuf := &bytes.Buffer{}
	if err := pem.Encode(pkBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: pkBytesRaw}); err != nil {
		return nil, nil, errors.Wrapf(err, "Could not pem encode private key")
	}

	pub, err := ssh.NewPublicKey(&pk.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Could not get public key from private key")
	}

	// Marshal into authorized key file format
	// Like ssh.MarshalAuthorizedKey() but allows adding a comment
	pubkeyBuf := &bytes.Buffer{}
	pubkeyBuf.WriteString(pub.Type())
	pubkeyBuf.WriteByte(' ')
	b64 := base64.NewEncoder(base64.StdEncoding, pubkeyBuf)
	b64.Write(pub.Marshal())
	b64.Close()
	pubkeyBuf.WriteByte(' ')
	pubkeyBuf.WriteString(comment)
	pubkeyBuf.WriteByte('\n')
	return pubkeyBuf.Bytes(), pkBuf.Bytes(), nil
}

func writeKeyPair(pubkeyPath string, pubkey []byte, privatekeyPath string, privatekey []byte) error {
	err := ioutil.WriteFile(pubkeyPath, pubkey, 0644)
	if err != nil {
		return errors.Wrapf(err, "Could not write pubkey to file")
	}
	err = ioutil.WriteFile(privatekeyPath, privatekey, 0600)
	if err != nil {
		return errors.Wrapf(err, "Could not write pubkey to file")
	}
	return nil
}

func writeSSHCert(certPath string, cert []byte) error {
	err := ioutil.WriteFile(certPath, cert, 0644)
	if err != nil {
		return errors.Wrapf(err, "Could not write pub cert to file")
	}
	return nil
}
