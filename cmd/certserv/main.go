package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/leelynne/sshcertifier/service"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "sshcertifier"
	app.Version = "0.0.1"
	app.Usage = "Run a service to sign users ssh public keys"
	app.Commands = []cli.Command{
		{
			Name:  "server",
			Usage: "Run the ssh ceritifier service",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "region, r",
					Value: "us-west-2",
					Usage: "AWS region to run in.",
				},
				cli.StringFlag{
					Name:  "cert, c",
					Value: "/sshcert/cert1",
					Usage: "SSM key for the ssh CA private key",
				},
				cli.StringFlag{
					Name:  "app, a",
					Value: "/sshcert/oauthconf/app1",
					Usage: "SSM key for the oauth config",
				},
			},
			Action: func(c *cli.Context) error {
				pk, oauthConf, err := service.LoadServerConfig(context.Background(),
					c.String("region"),
					c.String("cert"),
					c.String("app"),
				)
				if err != nil {
					panic(err)
				}
				serv, err := service.New(region, pk, nil, oauthConf)
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
			},
		},
		{
			Name:  "uploadca",
			Usage: "Upload the ssh ca to AWS secret manager",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name, n",
					Value: "/sshcert/cert1",
					Usage: "Name of the key to use in secret manager",
				},
				cli.StringFlag{
					Name:  "cafile, c",
					Value: "ca",
					Usage: "Name of the file with the SSH CA private key",
				},
				cli.StringFlag{
					Name:  "kmskey, k",
					Value: "sshcertifier",
					Usage: "Name of the KMS key used to encrypt the SSH CA",
				},
				cli.StringFlag{
					Name:  "region, r",
					Value: "us-west-2",
					Usage: "AWS region to store the CA in",
				},
			},
			Action: func(c *cli.Context) error {
				return service.StoreCA(context.Background(),
					c.String("region"),
					c.String("name"),
					c.String("kmskey"),
					c.String("cafile"))
			},
		},
		{
			Name:  "uploadoauth",
			Usage: "Upload the oauth conf AWS secret manager",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "app, a",
					Value: "/sshcert/oauthconf/app1",
					Usage: "Name of the key to use in secret manager",
				},
				cli.StringFlag{
					Name:  "conffile, c",
					Value: "oauthconf.json",
					Usage: "Name of the file with the oauth conf",
				},
				cli.StringFlag{
					Name:  "kmskey, k",
					Value: "sshcertifier",
					Usage: "Name of the KMS key used to encrypt the SSH CA",
				},
				cli.StringFlag{
					Name:  "region, r",
					Value: "us-west-2",
					Usage: "AWS region to store the oauth config",
				},
			},
			Action: func(c *cli.Context) error {
				return service.StoreOauth(context.Background(),
					c.String("region"),
					c.String("app"),
					c.String("kmskey"),
					c.String("conffile"))
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
