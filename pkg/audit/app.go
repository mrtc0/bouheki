package audit

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"

	"github.com/mrtc0/bouheki/pkg/audit/fileaccess"
	"github.com/mrtc0/bouheki/pkg/audit/mount"
	"github.com/mrtc0/bouheki/pkg/audit/network"
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
	app.Version = "0.0.10"
	app.Usage = "..."

	flags := []cli.Flag{&configFlag}

	app.Flags = flags

	app.Action = func(c *cli.Context) error {
		path := c.String("config")
		conf, err := config.NewConfig(path)
		if err != nil {
			log.Error(err)
			return nil
		}
		if !utils.AmIRootUser() {
			return errors.New("Must be run as root user")
		}

		log.SetFormatter(conf.Log.Format)
		log.SetOutput(conf.Log.Output)
		log.SetRotation(conf.Log.Output, conf.Log.MaxSize, conf.Log.MaxAge)
		log.SetLabel(conf.Log.Labels)

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(3)

		go fileaccess.RunAudit(ctx, &wg, conf)
		go network.RunAudit(ctx, &wg, conf)
		go mount.RunAudit(ctx, &wg, conf)

		wg.Wait()
		log.Info("Terminate all audit.")
		return nil
	}

	if os.Getenv("BOUHEKI_SKIP_COMPATIBLE_CHECK") == "" {
		err := utils.IsCompatible()
		if err != nil {
			log.Error(err)
		}
	}

	return app
}
