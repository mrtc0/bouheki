package network

import (
	"bytes"
	"encoding/binary"

	"github.com/mrtc0/bouheki/pkg/bpf"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
	"github.com/sirupsen/logrus"

	"github.com/aquasecurity/libbpfgo"
)

const TASK_COMM_LEN = 16
const NEW_UTS_LEN = 64
const PADDING_LEN = 7
const SRCIP_LEN = 4
const DSTIP_LEN = 4

type eventHeader struct {
	CGroupID  uint64
	PID       uint32
	EventType int32
	Nodename  [NEW_UTS_LEN + 1]byte
	Command   [TASK_COMM_LEN]byte
	_         [PADDING_LEN]byte
}

type eventBlockedIPv4 struct {
	SrcIP    [SRCIP_LEN]byte
	DstIP    [DSTIP_LEN]byte
	DstPort  uint16
	Op       uint8
	Action   uint8
	SockType uint8
}

func (e *eventBlockedIPv4) ActionResult() string {
	switch e.Action {
	case 0:
		return "MONITOR"
	case 1:
		return "BLOCKED"
	default:
		return "UNKNOWN"
	}
}

const (
	objName = "restricted-network"
)

func setupBPFProgram() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-network.bpf.o")
	if err != nil {
		return nil, err
	}
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, objName)
	if err != nil {
		return nil, err
	}
	err = mod.BPFLoadObject()
	if err != nil {
		return nil, err
	}

	return mod, nil
}

func loadBytecode(mode string) ([]byte, string, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-network.bpf.o")
	if err != nil {
		return nil, "", err
	}
	return bytecode, "restricted-network", nil
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

	err = mgr.SetConfig()
	if err != nil {
		log.Fatal(err)
	}

	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	for {
		eventBytes := <-eventsChannel
		header, body, err := parseEvent(eventBytes)
		if err != nil {
			log.Error(err)
		}

		log.WithFields(logrus.Fields{
			"Action":   body.ActionResult(),
			"Hostname": nodename2string(header.Nodename),
			"PID":      header.PID,
			"Comm":     comm2string(header.Command),
			"Addr":     byte2IPv4(body.DstIP),
			"Port":     body.DstPort,
			"Protocol": sockTypeToProtocolName(body.SockType),
		}).Info("Traffic is trapped in the filter.")
	}
}

func parseEvent(eventBytes []byte) (eventHeader, eventBlockedIPv4, error) {
	buf := bytes.NewBuffer(eventBytes)
	header, err := parseEventHeader(buf)
	if err != nil {
		return eventHeader{}, eventBlockedIPv4{}, err
	}
	body, err := parseEventBlockedIPv4(buf)
	if err != nil {
		return eventHeader{}, eventBlockedIPv4{}, err
	}

	return header, body, nil
}

func parseEventHeader(buf *bytes.Buffer) (eventHeader, error) {
	var header eventHeader
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return eventHeader{}, err
	}
	return header, nil
}

func parseEventBlockedIPv4(buf *bytes.Buffer) (eventBlockedIPv4, error) {
	var body eventBlockedIPv4
	if err := binary.Read(buf, binary.LittleEndian, &body); err != nil {
		return eventBlockedIPv4{}, err
	}

	return body, nil
}
