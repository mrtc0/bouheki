package commands

import (
	"github.com/mrtc0/bouheki/pkg/commands/network"
	log "github.com/mrtc0/bouheki/pkg/log"
	"github.com/mrtc0/bouheki/pkg/utils"
	"github.com/urfave/cli/v2"
)

var (
	configFlag = cli.StringFlag{
		Name:    "config",
		Value:   "bouheki.yaml",
		Usage:   "config file path",
		EnvVars: []string{"BOUHEKI_CONFIG_PATH"},
	}
)

func NewApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "bouheki"
	app.Version = "0.1"
	app.Usage = "..."

	flags := []cli.Flag{&configFlag}

	app.Flags = flags

	app.Action = network.Run

	err := utils.IsCompatible()
	if err != nil {
		log.Error(err)
	}

	return app
}
