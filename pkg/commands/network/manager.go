package network

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

const (
	MODE_MONITOR uint32 = 0
	MODE_BLOCK   uint32 = 1

	TARGET_HOST      uint32 = 0
	TAREGT_CONTAINER uint32 = 1

	CONFIG_BPF_TABLE = "b_config"

	/*
		+---------------+---------------+
		| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
		+---------------+---------------+
		|      MODE     |     TARGET    |
		+---------------+---------------+
	*/
	MAP_SIZE = 8

	MAP_MODE_START   = 0
	MAP_MODE_END     = 4
	MAP_TARGET_START = 4
	MAP_TARGET_END   = 8
)

type Manager struct {
	mod    *libbpfgo.Module
	config *config.Config
}

func (m *Manager) SetConfig() error {
	err := m.setConfigMap()
	if err != nil {
		return err
	}
	err = m.setAllowList()
	if err != nil {
		return err
	}
	err = m.setDenyList()
	if err != nil {
		return err
	}
	err = m.setAllowedCommandList()
	if err != nil {
		return err
	}
	err = m.setDenyCommandList()
	if err != nil {
		return err
	}
	err = m.attach()
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) Start(eventsChannel chan []byte) error {
	rb, err := m.mod.InitRingBuf("audit_events", eventsChannel)

	if err != nil {
		return err
	}

	rb.Start()

	return nil
}

func (m *Manager) attach() error {
	programs := []string{"socket_connect"}
	for _, progName := range programs {
		prog, err := m.mod.GetProgram(progName)

		if err != nil {
			return err
		}

		_, err = prog.AttachLSM()
		if err != nil {
			return err
		}

		log.Debug(fmt.Sprintf("%s attached.", progName))
	}

	return nil
}

func (m *Manager) setMode(table *libbpfgo.BPFMap, key []byte) error {
	if m.config.IsRestricted() {
		binary.LittleEndian.PutUint32(key[MAP_MODE_START:MAP_MODE_END], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_MODE_START:MAP_MODE_END], MODE_MONITOR)
	}

	err := table.Update(uint8(0), key)
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setTarget(table *libbpfgo.BPFMap, key []byte) error {
	if m.config.IsOnlyContainer() {
		binary.LittleEndian.PutUint32(key[MAP_TARGET_START:MAP_TARGET_END], TAREGT_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_TARGET_START:MAP_TARGET_END], TARGET_HOST)
	}

	err := table.Update(uint8(0), key)
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setConfigMap() error {
	config, err := m.mod.GetMap(CONFIG_BPF_TABLE)
	if err != nil {
		return err
	}

	key := make([]byte, MAP_SIZE)

	m.setMode(config, key)
	m.setTarget(config, key)

	return nil
}

func (m *Manager) setAllowedCommandList() error {
	commands, err := m.mod.GetMap("allowed_commands")
	if err != nil {
		return err
	}

	for _, c := range m.config.Network.Command.Allow {
		err = commands.Update(byteToKey([]byte(c)), uint8(0))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDenyCommandList() error {
	commands, err := m.mod.GetMap("deny_commands")
	if err != nil {
		return err
	}

	for _, c := range m.config.Network.Command.Deny {
		err = commands.Update(byteToKey([]byte(c)), uint8(0))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setAllowList() error {
	allowlist, err := m.mod.GetMap("allowlist")
	if err != nil {
		return err
	}

	for _, s := range m.config.Network.CIDR.Allow {
		allowAddresses, err := parseCIDR(s)
		if err != nil {
			return err
		}
		err = allowlist.Update(ipToKey(*allowAddresses), uint8(0))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDenyList() error {
	denylist, err := m.mod.GetMap("denylist")
	if err != nil {
		return err
	}

	for _, s := range m.config.Network.CIDR.Deny {
		denyAddresses, err := parseCIDR(s)
		if err != nil {
			return err
		}
		err = denylist.Update(ipToKey(*denyAddresses), uint8(0))
		if err != nil {
			return err
		}
	}

	return nil
}

func ipToKey(n net.IPNet) []byte {
	prefixLen, _ := n.Mask.Size()

	key := make([]byte, 16)

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	return key
}

func byteToKey(b []byte) []byte {
	key := make([]byte, 16)
	copy(key[0:], b)
	return key
}

func parseCIDR(cidr string) (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return n, nil
}
