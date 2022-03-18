package fileaccess

import (
	"C"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/bpf"
	log "github.com/mrtc0/bouheki/pkg/log"
)
import (
	"bytes"
	"encoding/binary"
	"os"
	"os/signal"

	"github.com/mrtc0/bouheki/pkg/audit/helpers"
	"github.com/mrtc0/bouheki/pkg/config"
)

const (
	BPF_OBJECT_NAME        = "restricted-file"
	BPF_PROGRAM_NAME       = "restricted_file_open"
	ALLOWED_FILES_MAP_NAME = "allowed_access_files"
	DENIED_FILES_MAP_NAME  = "denied_access_files"

	NEW_UTS_LEN   = 64
	PATH_MAX      = 255
	TASK_COMM_LEN = 16
)

type auditLog struct {
	CGroupID      uint64
	PID           uint32
	Ret           int32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [TASK_COMM_LEN]byte
	ParentCommand [TASK_COMM_LEN]byte
	Path          [PATH_MAX]byte
}

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

func RunAudit(conf *config.Config) error {
	if !conf.RestrictedFileAccessConfig.Enable {
		return nil
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	mod, err := setupBPFProgram()
	if err != nil {
		log.Fatal(err)
	}
	defer mod.Close()

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
	lostChannel := make(chan uint64)
	mgr.Start(eventChannel, lostChannel)

	go func() {
		for {
			eventBytes := <-eventChannel
			event, err := parseEvent(eventBytes)
			if err != nil {
				log.Error(err)
			}

			auditLog := newAuditLog(event)
			auditLog.Info()
		}
	}()

	<-quit
	mgr.Stop()

	return nil
}

func newAuditLog(event auditLog) log.RestrictedFileAccessLog {
	auditEvent := log.AuditEventLog{
		Action:     retToaction(event.Ret),
		Hostname:   helpers.NodenameToString(event.Nodename),
		PID:        event.PID,
		Comm:       helpers.CommToString(event.Command),
		ParentComm: helpers.CommToString(event.ParentCommand),
	}

	fileAccessLog := log.RestrictedFileAccessLog{
		AuditEventLog: auditEvent,
		Path:          pathToString(event.Path),
	}

	return fileAccessLog
}

func parseEvent(eventBytes []byte) (auditLog, error) {
	buf := bytes.NewBuffer(eventBytes)
	var event auditLog
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return auditLog{}, err
	}

	return event, nil
}

func retToaction(ret int32) string {
	if ret == 0 {
		return "ALLOWED"
	} else {
		return "BLOCKED"
	}
}

func pathToString(path [PATH_MAX]byte) string {
	var s string
	for _, b := range path {
		if b != 0x00 {
			s += string(b)
		} else {
			break
		}
	}
	return s
}
