package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/leelynne/sshcertifier/client"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "certclient"
	app.Version = "0.0.1"
	app.Usage = "Create and sign ssh public key"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "endpoint, e",
			Value: "https://sshcertifier.example.com",
			Usage: "Endpoint of sshceritifer service.",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "certify",
			Usage: "add a task to the list",
			Action: func(c *cli.Context) error {
				logger := log.New(os.Stdout, "certclient", log.LstdFlags)
				cc, err := client.New(c.String("endpoint"), false, "", logger)
				if err != nil {
					return printErr(err)
				}
				cu, err := cc.NewUser()
				if err != nil {
					return printErr(err)
				}
				err = cc.CertifyUser(cu)
				if err != nil {
					return printErr(err)
				}

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
					Value: "sshca",
					Usage: "Name of the KMS key used to encrypt the SSH CA",
				},
				cli.StringFlag{
					Name:  "region, r",
					Value: "us-west-2",
					Usage: "AWS region to store the CA in",
				},
			},
			Action: func(c *cli.Context) error {
				return client.Storekey(context.Background(),
					c.String("name"), c.String("kmskey"), c.String("cafile"))
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func printErr(err error) error {
	fmt.Println(err.Error())
	return err
}

/*
func makeToken() (token string, e error) {
	sess := session.New()
	stsAPI := sts.New(sess)
	request, _ := stsAPI.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	return request.Presign(15 * time.Minute)
}
*/
