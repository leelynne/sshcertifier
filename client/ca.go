package client

import (
	"context"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	secman "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func Storekey(ctx context.Context, name, kmsKeyID, cafile string) error {
	pkBytes, err := ioutil.ReadFile(cafile)
	if err != nil {
		panic(errors.Wrapf(err, "Couldn't read ca"))
	}
	_, err = ssh.ParsePrivateKey(pkBytes)

	if err != nil {
		panic(errors.Wrapf(err, "Couldn't parse private key"))
	}

	sess := session.New(aws.NewConfig().WithRegion("us-west-2"))
	secserv := secman.New(sess)
	req := &secman.CreateSecretInput{
		Name:         aws.String(name),
		Description:  aws.String("SSH CA Cert"),
		KmsKeyId:     aws.String(kmsKeyID),
		SecretBinary: pkBytes,
	}
	_, err = secserv.CreateSecretWithContext(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "Failed to create secret to store SSH CA")
	}
	return nil
}
