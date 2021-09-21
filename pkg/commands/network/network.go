package network

import (
	"fmt"

	"github.com/mrtc0/bouheki/pkg/bpf"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
	"github.com/urfave/cli/v2"
)

func loadBytecode(mode string) ([]byte, string, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-network.bpf.o")
	if err != nil {
		return nil, "", err
	}
	return bytecode, "restricted-network", nil
}

func Run(ctx *cli.Context) error {
	path := ctx.String("config")
	conf, err := config.NewConfig(path)
	if err != nil {
		return err
	}

	bytecode, objName, err := loadBytecode(conf.Network.Mode)
	if err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("Allowed Networks: %v", conf.Network.Allow))
	log.Debug(fmt.Sprintf("Denied Networks: %v", conf.Network.Deny))

	RunAudit(bytecode, objName, conf)

	return nil
}
