package main

import (
	"context"
	"crypto/tls"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	secman "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/leelynne/sshcertifier/service"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	tlsconf, err := getTLSConfig()
	if err != nil {
		panic(err)
	}
	certSecretID := "/sshcert/cert1"
	sess := session.New(aws.NewConfig().WithRegion("us-west-2"))
	secserv := secman.New(sess)
	req := &secman.GetSecretValueInput{
		SecretId: aws.String(certSecretID),
	}
	out, err := secserv.GetSecretValueWithContext(context.Background(), req)
	if err != nil {
		panic(errors.Wrapf(err, "Could get CA from secrets manager - '%s'", certSecretID))
	}

	pk, err := ssh.ParsePrivateKey(out.SecretBinary)
	if err != nil {
		panic(errors.Wrapf(err, "couldn't parse private ca key"))
	}
	serv, err := service.New(pk, nil)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go serv.Run(ctx, tlsconf)
	<-interrupt
	cancel()
	serv.Stop(ctx)
}

func getTLSConfig() (*tls.Config, error) {
	cert, err := gencert()
	if err != nil {
		return nil, errors.Wrapf(err, "Could not generate local TLS cert")
	}
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		/*CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},*/
		Certificates: []tls.Certificate{cert},
	}, nil
}
