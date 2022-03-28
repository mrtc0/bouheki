package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

const (
	MODE_MONITOR uint32 = 0
	MODE_BLOCK   uint32 = 1

	TARGET_HOST      uint32 = 0
	TAREGT_CONTAINER uint32 = 1

	// BPF Map Names
	RESTRICT_NETWORK_CONFIG_MAP_NAME = "network_bouheki_config_map"
	ALLOWED_V4_CIDR_LIST_MAP_NAME    = "allowed_v4_cidr_list"
	ALLOWED_V6_CIDR_LIST_MAP_NAME    = "allowed_v6_cidr_list"
	DENIED_V4_CIDR_LIST_MAP_NAME     = "denied_v4_cidr_list"
	DENIED_V6_CIDR_LIST_MAP_NAME     = "denied_v6_cidr_list"
	ALLOWED_UID_LIST_MAP_NAME        = "allowed_uid_list"
	DENIED_UID_LIST_MAP_NAME         = "denied_uid_list"
	ALLOWED_GID_LIST_MAP_NAME        = "allowed_gid_list"
	DENIED_GID_LIST_MAP_NAME         = "denied_gid_list"
	ALLOWED_COMMAND_LIST_MAP_NAME    = "allowed_command_list"
	DENIED_COMMAND_LIST_MAP_NAME     = "denied_command_list"

	/*
	   +---------------+---------------+-------------------+-------------------+-------------------+
	   | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12  | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
	   +---------------+---------------+-------------------+-------------------+-------------------+
	   |      MODE     |     TARGET    | Allow Command Size|  Allow UID Size   | Allow GID Size    |
	   +---------------+---------------+-------------------+-------------------+-------------------+
	*/

	MAP_SIZE                = 20
	MAP_MODE_START          = 0
	MAP_MODE_END            = 4
	MAP_TARGET_START        = 4
	MAP_TARGET_END          = 8
	MAP_ALLOW_COMMAND_INDEX = 8
	MAP_ALLOW_UID_INDEX     = 12
	MAP_ALLOW_GID_INDEX     = 16
)

type Manager struct {
	mod         *libbpfgo.Module
	config      *config.Config
	rb          *libbpfgo.RingBuffer
	dnsResolver DNSResolver
}

type IPAddress struct {
	address  net.IP
	cidrMask net.IPMask
	key      []byte
}

func (i *IPAddress) isV6address() bool {
	return i.address.To4() == nil
}

func (i *IPAddress) ipAddressToBPFMapKey() []byte {
	ip := net.IPNet{IP: i.address.Mask(i.cidrMask), Mask: i.cidrMask}

	if i.isV6address() {
		i.key = ipv6ToKey(ip)
	} else {
		i.key = ipv4ToKey(ip)
	}

	return i.key
}

type DNSResolver interface {
	Resolve(host string, recordType uint16) (*DNSAnswer, error)
}

type DefaultResolver struct {
	config  *dns.ClientConfig
	client  *dns.Client
	message *dns.Msg
	mux     sync.Mutex
}

func (m *Manager) SetConfigToMap() error {
	if err := m.setConfigMap(); err != nil {
		return err
	}
	if err := m.setAllowedCIDRList(); err != nil {
		return err
	}
	if err := m.setDeniedCIDRList(); err != nil {
		return err
	}
	if err := m.initDomainList(); err != nil {
		return err
	}
	if err := m.setAllowedCommandList(); err != nil {
		return err
	}
	if err := m.setDeniedCommandList(); err != nil {
		return err
	}
	if err := m.setAllowedUIDList(); err != nil {
		return err
	}
	if err := m.setDeniedUIDList(); err != nil {
		return err
	}
	if err := m.setAllowedGIDList(); err != nil {
		return err
	}
	if err := m.setDeniedGIDList(); err != nil {
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
	m.rb = rb

	return nil
}

func (m *Manager) Stop() {
	m.rb.Stop()
}

func (m *Manager) Close() {
	m.rb.Close()
}

func (m *Manager) Attach() error {
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

func (m *Manager) setMode(table *libbpfgo.BPFMap, key []byte) []byte {
	if m.config.IsRestrictedMode("network") {
		binary.LittleEndian.PutUint32(key[MAP_MODE_START:MAP_MODE_END], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_MODE_START:MAP_MODE_END], MODE_MONITOR)
	}

	return key
}

func (m *Manager) setTarget(table *libbpfgo.BPFMap, key []byte) []byte {
	if m.config.IsOnlyContainer("network") {
		binary.LittleEndian.PutUint32(key[MAP_TARGET_START:MAP_TARGET_END], TAREGT_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_TARGET_START:MAP_TARGET_END], TARGET_HOST)
	}

	return key
}

func (m *Manager) setConfigMap() error {
	configMap, err := m.mod.GetMap(RESTRICT_NETWORK_CONFIG_MAP_NAME)
	if err != nil {
		return err
	}

	key := make([]byte, MAP_SIZE)

	key = m.setMode(configMap, key)
	key = m.setTarget(configMap, key)

	binary.LittleEndian.PutUint32(key[MAP_ALLOW_COMMAND_INDEX:MAP_ALLOW_COMMAND_INDEX+4], uint32(len(m.config.RestrictedNetworkConfig.Command.Allow)))
	binary.LittleEndian.PutUint32(key[MAP_ALLOW_UID_INDEX:MAP_ALLOW_UID_INDEX+4], uint32(len(m.config.RestrictedNetworkConfig.UID.Allow)))
	binary.LittleEndian.PutUint32(key[MAP_ALLOW_GID_INDEX:MAP_ALLOW_GID_INDEX+4], uint32(len(m.config.RestrictedNetworkConfig.GID.Allow)))

	k := uint8(0)
	err = configMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&key[0]))

	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setAllowedCommandList() error {
	commands, err := m.mod.GetMap(ALLOWED_COMMAND_LIST_MAP_NAME)
	if err != nil {
		return err
	}

	for _, c := range m.config.RestrictedNetworkConfig.Command.Allow {
		key := byteToKey([]byte(c))
		value := uint8(0)
		err = commands.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedCommandList() error {
	commands, err := m.mod.GetMap(DENIED_COMMAND_LIST_MAP_NAME)
	if err != nil {
		return err
	}

	for _, c := range m.config.RestrictedNetworkConfig.Command.Deny {
		key := byteToKey([]byte(c))
		value := uint8(0)
		err = commands.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setAllowedUIDList() error {
	uids, err := m.mod.GetMap(ALLOWED_UID_LIST_MAP_NAME)
	if err != nil {
		return err
	}
	for _, uid := range m.config.RestrictedNetworkConfig.UID.Allow {
		key := uintToKey(uid)
		value := uint8(0)
		err = uids.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedUIDList() error {
	uids, err := m.mod.GetMap(DENIED_UID_LIST_MAP_NAME)
	if err != nil {
		return err
	}
	for _, uid := range m.config.RestrictedNetworkConfig.UID.Deny {
		key := uintToKey(uid)
		value := uint8(0)
		err = uids.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setAllowedGIDList() error {
	gids, err := m.mod.GetMap(ALLOWED_GID_LIST_MAP_NAME)
	if err != nil {
		return err
	}
	for _, gid := range m.config.RestrictedNetworkConfig.GID.Allow {
		key := uintToKey(gid)
		value := uint8(0)
		err = gids.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedGIDList() error {
	gids, err := m.mod.GetMap(DENIED_UID_LIST_MAP_NAME)
	if err != nil {
		return err
	}
	for _, gid := range m.config.RestrictedNetworkConfig.GID.Deny {
		key := uintToKey(gid)
		value := uint8(0)
		err = gids.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setAllowedCIDRList() error {
	for _, addr := range m.config.RestrictedNetworkConfig.CIDR.Allow {
		allowedAddress, err := cidrToBPFMapKey(addr)
		if err != nil {
			return err
		}
		if allowedAddress.isV6address() {
			err = m.cidrListUpdate(allowedAddress, ALLOWED_V6_CIDR_LIST_MAP_NAME)
			if err != nil {
				return err
			}
		} else {
			err = m.cidrListUpdate(allowedAddress, ALLOWED_V4_CIDR_LIST_MAP_NAME)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) setDeniedCIDRList() error {
	for _, addr := range m.config.RestrictedNetworkConfig.CIDR.Deny {
		deniedAddress, err := cidrToBPFMapKey(addr)
		if err != nil {
			return err
		}
		if deniedAddress.isV6address() {
			err = m.cidrListUpdate(deniedAddress, DENIED_V6_CIDR_LIST_MAP_NAME)
			if err != nil {
				return err
			}
		} else {
			err = m.cidrListUpdate(deniedAddress, DENIED_V4_CIDR_LIST_MAP_NAME)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) initDomainList() error {
	// TODO: refactor
	for _, domain := range m.config.RestrictedNetworkConfig.Domain.Deny {
		answer, err := m.ResolveAddressv4(domain)
		if err != nil {
			continue
		}

		err = m.setDeniedDomainList(answer)
		if err != nil {
			return err
		}

		answer, err = m.ResolveAddressv6(domain)
		if err != nil {
			continue
		}

		err = m.setDeniedDomainList(answer)
		if err != nil {
			return err
		}
	}

	for _, domain := range m.config.RestrictedNetworkConfig.Domain.Allow {
		answer, err := m.ResolveAddressv4(domain)
		if err != nil {
			log.Debug(fmt.Sprintf("%s (A) resolve failed. %s\n", domain, err))
			continue
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		err = m.setAllowedDomainList(answer)
		if err != nil {
			return err
		}

		answer, err = m.ResolveAddressv6(domain)
		if err != nil {
			log.Debug(fmt.Sprintf("%s (AAAA) resolve failed. %s\n", domain, err))
			continue
		}

		log.Debug(fmt.Sprintf("%s (AAAA) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		err = m.setAllowedDomainList(answer)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setAllowedDomainList(answer *DNSAnswer) error {
	allowedAddresses, err := domainNameToBPFMapKey(answer.Domain, answer.Addresses)
	if err != nil {
		return err
	}

	for _, addr := range allowedAddresses {
		if addr.isV6address() {
			if err = m.cidrListUpdate(addr, ALLOWED_V6_CIDR_LIST_MAP_NAME); err != nil {
				return err
			}
		} else {
			if err = m.cidrListUpdate(addr, ALLOWED_V4_CIDR_LIST_MAP_NAME); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) setDeniedDomainList(answer *DNSAnswer) error {
	deniedAddresses, err := domainNameToBPFMapKey(answer.Domain, answer.Addresses)
	if err != nil {
		return err
	}

	for _, addr := range deniedAddresses {
		if addr.isV6address() {
			err = m.cidrListUpdate(addr, DENIED_V6_CIDR_LIST_MAP_NAME)
			if err != nil {
				return err
			}
		} else {
			err = m.cidrListUpdate(addr, DENIED_V4_CIDR_LIST_MAP_NAME)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) cidrListDeleteKey(mapName string, key []byte) error {
	cidr_list, err := m.mod.GetMap(mapName)
	if err != nil {
		return err
	}

	if err := cidr_list.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
		return err
	}
	return nil
}

func (m *Manager) cidrListUpdate(addr IPAddress, mapName string) error {
	cidr_list, err := m.mod.GetMap(mapName)
	if err != nil {
		return err
	}
	value := uint8(0)
	// NOTE: Slices and arrays are supported but references should be passed to the first element in the slice or array.
	err = cidr_list.Update(unsafe.Pointer(&addr.key[0]), unsafe.Pointer(&value))
	if err != nil {
		return err
	}
	return nil
}

func cidrToBPFMapKey(cidr string) (IPAddress, error) {
	ipaddr := IPAddress{}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return ipaddr, err
	}
	ipaddr.address = n.IP
	ipaddr.cidrMask = n.Mask
	ipaddr.ipAddressToBPFMapKey()
	return ipaddr, nil
}

func domainNameToBPFMapKey(host string, addresses []net.IP) ([]IPAddress, error) {
	var addrs = []IPAddress{}
	for _, addr := range addresses {
		ipaddr := IPAddress{address: addr}
		if ipaddr.isV6address() {
			ipaddr.cidrMask = net.CIDRMask(128, 128)
		} else {
			ipaddr.cidrMask = net.CIDRMask(32, 32)
		}
		ipaddr.ipAddressToBPFMapKey()
		addrs = append(addrs, ipaddr)
	}

	return addrs, nil
}

func ipv4ToKey(n net.IPNet) []byte {
	key := make([]byte, 16)
	prefixLen, _ := n.Mask.Size()

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	return key
}

func ipv6ToKey(n net.IPNet) []byte {
	key := make([]byte, 20)
	prefixLen, _ := n.Mask.Size()

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	return key
}

func byteToKey(b []byte) []byte {
	key := make([]byte, 16)
	copy(key[0:], b)
	return key
}

func uintToKey(i uint) []byte {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key[0:4], uint32(i))
	return key
}
