package network

import (
	"errors"

	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
	"github.com/mrtc0/bouheki/pkg/utils"
	"github.com/urfave/cli/v2"
)

func Run(ctx *cli.Context) error {
	path := ctx.String("config")
	conf, err := config.NewConfig(path)
	if err != nil {
		return err
	}

	if !utils.AmIRootUser() {
		return errors.New("Must be run as root")
	}

	log.SetFormatter(conf.Log.Format)
	log.SetOutput(conf.Log.Output)
	log.SetRotation(conf.Log.Output, conf.Log.MaxSize, conf.Log.MaxAge)

	RunAudit(conf)

	return nil
}
