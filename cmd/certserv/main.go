package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	secman "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/leelynne/sshcertifier/service"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func main() {
	app := cli.NewApp()
	app.Name = "sshcertifier"
	app.Version = "0.0.1"
	app.Usage = "Run a service to sign users ssh public keys"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "region, r",
			Usage: "AWS region to run in.",
		},
		cli.StringFlag{
			Name:  "cert, c",
			Value: "/sshcert/cert1",
			Usage: "SSM key for the ssh CA private key",
		},
	}
	app.Action = func(c *cli.Context) error {
		certSecretID := c.String("cert")
		sess := session.New(aws.NewConfig().WithRegion(c.String("region")))
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
		serv, err := service.New(pk, nil)
		if err != nil {
			panic(err)
		}
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

		ctx, cancel := context.WithCancel(context.Background())
		go serv.Run(ctx, 8888)
		<-interrupt
		cancel()
		serv.Stop(ctx)
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
