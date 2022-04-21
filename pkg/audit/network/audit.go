package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/audit/helpers"
	"github.com/mrtc0/bouheki/pkg/bpf"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	UPDATE_INTERVAL = 5
	TASK_COMM_LEN   = 16
	NEW_UTS_LEN     = 64
	PADDING_LEN     = 7
	SRCIP_V4_LEN    = 4
	DSTIP_V4_LEN    = 4
	SRCIP_V6_LEN    = 16
	DSTIP_V6_LEN    = 16

	ACTION_MONITOR        uint8 = 0
	ACTION_BLOCKED        uint8 = 1
	ACTION_MONITOR_STRING       = "MONITOR"
	ACTION_BLOCKED_STRING       = "BLOCKED"
	ACTION_UNKNOWN_STRING       = "UNKNOWN"

	BLOCKED_IPV4 int32 = 0
	BLOCKED_IPV6 int32 = 1

	LSM_HOOK_POINT_CONNECT uint8 = 0
	LSM_HOOK_POINT_SENDMSG uint8 = 1
)

type eventHeader struct {
	CGroupID      uint64
	PID           uint32
	EventType     int32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [TASK_COMM_LEN]byte
	ParentCommand [TASK_COMM_LEN]byte
	_             [PADDING_LEN]byte
}

type detectEvent interface {
	ActionResult() string
}

type detectEventIPv4 struct {
	SrcIP        [SRCIP_V4_LEN]byte
	DstIP        [DSTIP_V4_LEN]byte
	DstPort      uint16
	LsmHookPoint uint8
	Action       uint8
	SockType     uint8
}

type detectEventIPv6 struct {
	SrcIP        [SRCIP_V6_LEN]byte
	DstIP        [DSTIP_V6_LEN]byte
	DstPort      uint16
	LsmHookPoint uint8
	Action       uint8
	SockType     uint8
}

func (e detectEventIPv4) ActionResult() string {
	switch e.Action {
	case ACTION_MONITOR:
		return ACTION_MONITOR_STRING
	case ACTION_BLOCKED:
		return ACTION_BLOCKED_STRING
	default:
		return ACTION_UNKNOWN_STRING
	}
}

func (e detectEventIPv6) ActionResult() string {
	switch e.Action {
	case ACTION_MONITOR:
		return ACTION_MONITOR_STRING
	case ACTION_BLOCKED:
		return ACTION_BLOCKED_STRING
	default:
		return ACTION_UNKNOWN_STRING
	}
}

const (
	BPF_OBJECT_NAME = "restricted-network"
)

func setupBPFProgram() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-network.bpf.o")
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

func RunAudit(ctx context.Context, wg *sync.WaitGroup, conf *config.Config) error {
	log.Info("Launching the network audit...")
	defer wg.Done()

	if !conf.RestrictedNetworkConfig.Enable {
		log.Info("netwrok audit is disable. shutdown...")
		return nil
	}

	mod, err := setupBPFProgram()
	if err != nil {
		log.Fatal(err)
	}
	defer mod.Close()

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return err
	}

	mgr := Manager{
		mod:    mod,
		config: conf,
		dnsResolver: &DefaultResolver{
			config:  dnsConfig,
			client:  new(dns.Client),
			message: new(dns.Msg),
		},
	}

	if err = mgr.SetConfigToMap(); err != nil {
		log.Fatal(err)
	}

	if mgr.config.EnableDNSProxy() {
		for _, bindAddress := range mgr.config.DNSProxyConfig.BindAddresses {
			go func(bindAddress string) {
				log.Info(fmt.Sprintf("Launching the DNS Proxy %s...", bindAddress))
				err := mgr.StartDNSServer(bindAddress)
				if err != nil {
					log.Fatal(err)
				}
			}(bindAddress)
		}
	} else {
		log.Info("Start async DNS Resolver...")
		mgr.AsyncResolve()
	}

	if err = mgr.Attach(); err != nil {
		log.Fatal(err)
	}

	log.Info("Start the network audit.")
	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	go func() {
		for {
			eventBytes := <-eventsChannel
			header, body, err := parseEvent(eventBytes)
			if err != nil {
				if err == io.EOF {
					return
				}

				log.Error(err)
				continue
			}

			auditLog := newAuditLog(header, body)
			auditLog.Info()
		}
	}()

	<-ctx.Done()
	mgr.Close()
	log.Info("Terminated the network audit.")

	return nil
}

func newAuditLog(header eventHeader, body detectEvent) log.RestrictedNetworkLog {
	var (
		addr     string
		port     uint16
		socktype uint8
	)

	if header.EventType == BLOCKED_IPV6 {
		body := body.(detectEventIPv6)
		port = body.DstPort
		addr = net.ParseIP(byte2IPv6(body.DstIP)).String()
		socktype = body.SockType
	} else {
		body := body.(detectEventIPv4)
		port = body.DstPort
		addr = byte2IPv4(body.DstIP)
		socktype = body.SockType
	}

	auditEvent := log.AuditEventLog{
		Action:     body.ActionResult(),
		Hostname:   helpers.NodenameToString(header.Nodename),
		PID:        header.PID,
		Comm:       helpers.CommToString(header.Command),
		ParentComm: helpers.CommToString(header.ParentCommand),
	}

	networkLog := log.RestrictedNetworkLog{
		AuditEventLog: auditEvent,
		Addr:          addr,
		Domain:        dnsCache[addr],
		Port:          port,
		Protocol:      sockTypeToProtocolName(socktype),
	}

	return networkLog
}

func parseEvent(eventBytes []byte) (eventHeader, detectEvent, error) {
	buf := bytes.NewBuffer(eventBytes)
	header, err := parseEventHeader(buf)
	if err != nil {
		return eventHeader{}, detectEventIPv4{}, err
	}
	if header.EventType == BLOCKED_IPV4 {
		body, err := parseEventBlockedIPv4(buf)
		if err != nil {
			return eventHeader{}, detectEventIPv4{}, err
		}

		return header, body, nil
	} else if header.EventType == BLOCKED_IPV6 {
		body, err := parseEventBlockedIPv6(buf)
		if err != nil {
			return eventHeader{}, detectEventIPv6{}, err
		}

		return header, body, nil
	} else {
		return eventHeader{}, detectEventIPv4{}, err
	}
}

func parseEventHeader(buf *bytes.Buffer) (eventHeader, error) {
	var header eventHeader
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return eventHeader{}, err
	}
	return header, nil
}

func parseEventBlockedIPv4(buf *bytes.Buffer) (detectEventIPv4, error) {
	var body detectEventIPv4
	if err := binary.Read(buf, binary.LittleEndian, &body); err != nil {
		return detectEventIPv4{}, err
	}

	return body, nil
}

func parseEventBlockedIPv6(buf *bytes.Buffer) (detectEventIPv6, error) {
	var body detectEventIPv6
	if err := binary.Read(buf, binary.LittleEndian, &body); err != nil {
		return detectEventIPv6{}, err
	}

	return body, nil
}
