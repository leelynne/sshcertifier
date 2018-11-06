package main

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	secman "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func main() {
	pkBytes, err := ioutil.ReadFile("ca")
	if err != nil {
		panic(errors.Wrapf(err, "Couldn't read ca"))
	}
	_, err = ssh.ParsePrivateKey(pkBytes)

	if err != nil {
		panic(errors.Wrapf(err, "Couldn't parse private key"))
	}
	err = storekey(context.Background(), "/sshcert/cert1", "sshca", pkBytes)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(errors.Wrapf(err, "Failed to store ssh ca"))
	}
}

//func createKMSKey(name)
func storekey(ctx context.Context, name, kmsKeyID string, pk []byte) error {
	sess := session.New(aws.NewConfig().WithRegion("us-west-2"))
	secserv := secman.New(sess)
	req := &secman.CreateSecretInput{
		Name:         aws.String(name),
		Description:  aws.String("SSH CA Cert"),
		KmsKeyId:     aws.String(kmsKeyID),
		SecretBinary: pk,
	}
	_, err := secserv.CreateSecretWithContext(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "Failed to create secret to store SSH CA")
	}
	return nil
}

/*func createCAKey() error {

	pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return errors.Wrapf(err, "Failed to generate new private key")
	}
	//	pubkey := pk.Public()

	ecder, err := x509.MarshalECPrivateKey(pk)
	keypem, err := os.OpenFile("ssh-ca", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecder})

	sshPubkey, err := ssh.NewPublicKey(&pk.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "Couldn't create ssh pubkey from ecdsa pubkey")
	}
	out := ssh.MarshalAuthorizedKey(sshPubkey)
	ioutil.WriteFile("ssh-ca.pub", out, 0600)
	return nil
}
*/
