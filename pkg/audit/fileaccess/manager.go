package fileaccess

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

const (
	FILEACCESS_CONFIG = "fileopen_bouheki_config_map"
	MODE_MONITOR      = uint32(0)
	MODE_BLOCK        = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)
)

type Manager struct {
	mod    *libbpfgo.Module
	config *config.Config
	pb     *libbpfgo.PerfBuffer
}

func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	pb, err := m.mod.InitPerfBuf("fileopen_events", eventChannel, lostChannel, 1024)
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
	err := m.setModeAndTarget()
	if err != nil {
		return err
	}

	err = m.setAllowedFileAccessMap()
	if err != nil {
		return err
	}

	err = m.setDeniedFileAccessMap()
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setAllowedFileAccessMap() error {
	map_allowed_files, err := m.mod.GetMap(ALLOWED_FILES_MAP_NAME)
	if err != nil {
		return err
	}

	allowed_paths := m.config.RestrictedFileAccessConfig.Allow

	for i, path := range allowed_paths {
		key := uint8(i)
		value := []byte(path)
		err = map_allowed_files.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedFileAccessMap() error {
	map_denied_files, err := m.mod.GetMap(DENIED_FILES_MAP_NAME)
	if err != nil {
		return err
	}
	denied_paths := m.config.RestrictedFileAccessConfig.Deny

	for i, path := range denied_paths {
		key := uint8(i)
		value := []byte(path)

		keyPtr := unsafe.Pointer(&key)
		valuePtr := unsafe.Pointer(&value[0])
		err = map_denied_files.Update(keyPtr, valuePtr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setModeAndTarget() error {
	key := make([]byte, 8)
	configMap, err := m.mod.GetMap(FILEACCESS_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("fileaccess") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	if m.config.IsOnlyContainer("fileaccess") {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_HOST)
	}

	k := uint8(0)
	err = configMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&key[0]))
	if err != nil {
		return err
	}

	return nil
}
