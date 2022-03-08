package commands

import (
	"errors"
	"os"
	"os/signal"

	"github.com/mrtc0/bouheki/pkg/commands/fileaccess"
	"github.com/mrtc0/bouheki/pkg/commands/network"
	"github.com/mrtc0/bouheki/pkg/config"
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

	app.Action = func(c *cli.Context) error {
		path := c.String("config")
		conf, err := config.NewConfig(path)
		if err != nil {
			return nil
		}
		if !utils.AmIRootUser() {
			return errors.New("Must be run as root user")
		}

		log.SetFormatter(conf.Log.Format)
		log.SetOutput(conf.Log.Output)
		log.SetRotation(conf.Log.Output, conf.Log.MaxSize, conf.Log.MaxAge)

		go network.RunAudit(conf)
		go fileaccess.RunAudit(conf)

		quit := make(chan os.Signal)
		signal.Notify(quit, os.Interrupt)
		<-quit
		return nil
	}

	err := utils.IsCompatible()
	if err != nil {
		log.Error(err)
	}

	return app
}
