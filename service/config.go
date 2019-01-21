package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	secman "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

/*type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint struct {
		AuthURL  string
		TokenURL string
	}

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string
}*/

func LoadServerConfig(ctx context.Context, region, certSecretID, oauthConfID string) (caPrivateKey ssh.Signer, conf *oauth2.Config, e error) {
	sess := session.New(aws.NewConfig().WithRegion(region))
	secserv := secman.New(sess)

	req := &secman.GetSecretValueInput{
		SecretId: aws.String(certSecretID),
	}
	out, err := secserv.GetSecretValueWithContext(context.Background(), req)
	if err != nil {
		panic(errors.Wrapf(err, "Could not get CA from secrets manager - '%s'", certSecretID))
	}

	pk, err := ssh.ParsePrivateKey(out.SecretBinary)
	if err != nil {
		panic(errors.Wrapf(err, "couldn't parse private ca key"))
	}

	req = &secman.GetSecretValueInput{
		SecretId: aws.String(oauthConfID),
	}
	out, err = secserv.GetSecretValueWithContext(context.Background(), req)
	if err != nil {
		panic(errors.Wrapf(err, "Could not get oauth config from secrets manager - '%s'", oauthConfID))
	}
	oconf := &oauth2.Config{}
	err = json.Unmarshal(out.SecretBinary, oconf)
	if err != nil {
		panic(errors.Wrapf(err, "Couldn't parse oauth config file '%s'", oauthConfID))
	}

	return pk, oconf, nil
}

func StoreCA(ctx context.Context, region, name, kmsKeyAlias, cafile string) error {
	pkBytes, err := ioutil.ReadFile(cafile)
	if err != nil {
		panic(errors.Wrapf(err, "Couldn't read ca"))
	}
	_, err = ssh.ParsePrivateKey(pkBytes)

	if err != nil {
		panic(errors.Wrapf(err, "Couldn't parse private key"))
	}

	sess := session.New(aws.NewConfig().WithRegion(region))
	secserv := secman.New(sess)
	req := &secman.CreateSecretInput{
		Name:         aws.String(name),
		Description:  aws.String("SSH CA Cert"),
		KmsKeyId:     aws.String(fmt.Sprintf("alias/%s", kmsKeyAlias)),
		SecretBinary: pkBytes,
	}
	_, err = secserv.CreateSecretWithContext(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "Failed to create secret to store SSH CA")
	}
	return nil
}

func StoreOauth(ctx context.Context, region, oauthApp, kmsKeyAlias, oauthconfFile string) error {
	oabytes, err := ioutil.ReadFile(oauthconfFile)
	if err != nil {
		panic(errors.Wrapf(err, "Couldn't read oauth conf file"))
	}

	// Ensure the file parses
	oconf := &oauth2.Config{}
	err = json.Unmarshal(oabytes, oconf)
	if err != nil {
		return errors.Wrapf(err, "Couldn't parse oauth config file '%s'", oauthconfFile)
	}
	// Ensure it has the right stuff
	if oconf.ClientID == "" {
		return errors.New("Config missing ClientID")
	}
	if oconf.ClientSecret == "" {
		return errors.New("Config missing ClientSecret")
	}
	if oconf.RedirectURL == "" {
		return errors.New("Config missing RedirectURL")
	}
	if len(oconf.Scopes) == 0 {
		return errors.New("Config missing Scopes")
	}

	sess := session.New(aws.NewConfig().WithRegion(region))
	secserv := secman.New(sess)
	req := &secman.CreateSecretInput{
		Name:         aws.String(oauthApp),
		Description:  aws.String(fmt.Sprintf("Oauth config for app '%s'", oauthApp)),
		KmsKeyId:     aws.String(fmt.Sprintf("alias/%s", kmsKeyAlias)),
		SecretBinary: oabytes,
	}
	_, err = secserv.CreateSecretWithContext(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "Failed to create secret for oauth config for app '%s'", oauthApp)
	}
	return nil
}
