package main

import (
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
				cc, err := client.New(c.GlobalString("endpoint"), false, "", logger)
				if err != nil {
					return printErr(err)
				}

				code, err := cc.Auth()
				if err != nil {
					return printErr(err)
				}
				cu, err := cc.NewUser()
				if err != nil {
					return printErr(err)
				}
				err = cc.CertifyUser(cu, code)
				if err != nil {
					return printErr(err)
				}

				return nil
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
