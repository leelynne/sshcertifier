package main

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

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

	pkBytes, err := ioutil.ReadFile("ca")
	if err != nil {
		panic(errors.Wrapf(err, "Couldn't read ca"))
	}
	pk, err := ssh.ParsePrivateKey(pkBytes)
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
