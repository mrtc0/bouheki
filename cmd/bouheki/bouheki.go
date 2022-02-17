package main

import (
	"os"

	"github.com/mrtc0/bouheki/pkg/commands"
	log "github.com/sirupsen/logrus"
)

var (
	version = "dev"
)

func main() {
	app := commands.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
