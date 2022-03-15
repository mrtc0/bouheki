package mount

import (
	"fmt"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

const (
	MOUNT_CONFIG             = "mount_bouheki_config_map"
	MOUNT_DENIED_SOURCE_LIST = "mount_denied_source_list"
	MODE_MONITOR             = uint32(0)
	MODE_BLOCK               = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)
)

type Manager struct {
	mod    *libbpfgo.Module
	config *config.Config
	pb     *libbpfgo.PerfBuffer
}

func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	pb, err := m.mod.InitPerfBuf("mount_events", eventChannel, lostChannel, 1024)
	if err != nil {
		return err
	}

	pb.Start()
	m.pb = pb

	return nil
}

func (m *Manager) Stop() {
	m.pb.Stop()
}

func (m *Manager) Close() {
	m.pb.Close()
}

func (m *Manager) Attach() error {
	prog, err := m.mod.GetProgram(BPF_PROGRAM_NAME)
	if err != nil {
		return err
	}

	_, err = prog.AttachLSM()
	if err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("%s attached.", BPF_PROGRAM_NAME))
	return nil
}

func (m *Manager) SetConfigToMap() error {
	map_denied_source_paths, err := m.mod.GetMap(MOUNT_DENIED_SOURCE_LIST)
	if err != nil {
		return err
	}

	denied_source_paths := m.config.RestrictedMountConfig.DenySourcePath
	for i, path := range denied_source_paths {
		key := uint8(i)
		value := []byte(path)
		err = map_denied_source_paths.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
		if err != nil {
			return err
		}
	}

	return nil
}
