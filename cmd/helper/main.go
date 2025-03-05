package main

import (
	"encoding/json"
	"os"

	oauth "github.com/haileyok/atproto-oauth-golang"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name: "Atproto Oauth Golang Helper",
		Commands: []*cli.Command{
			runGenerateJwks,
		},
	}

	app.RunAndExitOnError()
}

var runGenerateJwks = &cli.Command{
	Name: "generate-jwks",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "prefix",
			Required: false,
		},
	},
	Action: func(cmd *cli.Context) error {
		var prefix *string
		if cmd.String("prefix") != "" {
			inputPrefix := cmd.String("prefix")
			prefix = &inputPrefix
		}
		key, err := oauth.GenerateKey(prefix)
		if err != nil {
			return err
		}

		b, err := json.Marshal(key)
		if err != nil {
			return err
		}

		if err := os.WriteFile("./jwks.json", b, 0644); err != nil {
			return err
		}

		return nil
	},
}
