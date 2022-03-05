package fileaccess

import (
	"C"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/bpf"
	log "github.com/mrtc0/bouheki/pkg/log"
)
import (
	"fmt"

	"github.com/mrtc0/bouheki/pkg/config"
)

const (
	BPF_OBJECT_NAME        = "restricted-file"
	BPF_PROGRAM_NAME       = "restricted_file_open"
	ALLOWED_FILES_MAP_NAME = "allowed_access_files"
	DENIED_FILES_MAP_NAME  = "denied_access_files"
)

func setupBPFProgram() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-file.bpf.o")
	if err != nil {
		return nil, err
	}
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, BPF_OBJECT_NAME)
	if err != nil {
		return nil, err
	}

	if err = mod.BPFLoadObject(); err != nil {
		return nil, err
	}

	return mod, nil
}

func RunAudit(conf *config.Config) {
	mod, err := setupBPFProgram()
	if err != nil {
		log.Fatal(err)
	}

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	mgr.SetConfigToMap()
	if err != nil {
		log.Fatal(err)
	}

	mgr.Attach()

	eventChannel := make(chan []byte)
	mgr.Start(eventChannel)

	for {
		eventBytes := <-eventChannel
		fmt.Printf("%#v\n", eventBytes)
		fmt.Printf("%s\n", string(eventBytes))
	}
}
