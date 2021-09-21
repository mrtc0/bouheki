package network

import (
	"bytes"
	"encoding/binary"

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
	SrcIP   [SRCIP_LEN]byte
	DstIP   [DSTIP_LEN]byte
	DstPort uint16
	Op      uint8
}

func RunAudit(bytecode []byte, objName string, conf *config.Config) {
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, objName)
	if err != nil {
		log.Fatal(err)
	}
	err = mod.BPFLoadObject()
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
		buf := bytes.NewBuffer(eventBytes)
		hdr, err := parseEventHeader(buf)
		if err != nil {
			log.Error(err)
		}
		blocked, err := parseEvent(buf, &hdr)
		if err != nil {
			log.Error(err)
		}

		log.WithFields(logrus.Fields{
			"Action":   conf.Network.Mode,
			"Hostname": nodename2string(hdr.Nodename),
			"PID":      hdr.PID,
			"Comm":     comm2string(hdr.Command),
			"Addr":     byte2IPv4(blocked.DstIP),
			"Port":     blocked.DstPort,
		}).Info("Traffic is trapped in the filter.")
	}
}

func parseEventHeader(buf *bytes.Buffer) (eventHeader, error) {
	var hdr eventHeader
	err := binary.Read(buf, binary.LittleEndian, &hdr)
	if err != nil {
		return eventHeader{}, err
	}
	return hdr, nil
}

func parseEvent(buf *bytes.Buffer, hdr *eventHeader) (eventBlockedIPv4, error) {
	var body eventBlockedIPv4
	if err := binary.Read(buf, binary.LittleEndian, &body); err != nil {
		return eventBlockedIPv4{}, err
	}

	return body, nil
}
