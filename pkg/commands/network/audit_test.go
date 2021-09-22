package network

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

const (
	ACTION_MONITOR = "MONITOR"
	ACTION_BLOCKED = "BLOCKED"
)

type auditResult struct {
	header eventHeader
	body   eventBlockedIPv4
	cmd    *exec.Cmd
	err    error
}

func TestAuditBlockMode(t *testing.T) {
	fixture := "../../../testdata/block.yml"
	result := runAuditWithOnce(fixture, "curl", "https://10.0.1.1")

	assert.Nil(t, result.err)
	assert.Equal(t, result.body.ActionResult(), ACTION_BLOCKED)
	assert.Equal(t, int(result.header.PID), result.cmd.Process.Pid)
	assert.Equal(t, byte2IPv4(result.body.DstIP), "10.0.1.1")
}

func TestAuditMonitorMode(t *testing.T) {
	fixture := "../../../testdata/monitor.yml"
	result := runAuditWithOnce(fixture, "curl", "https://10.0.1.1")

	assert.Nil(t, result.err)
	assert.Equal(t, result.body.ActionResult(), ACTION_MONITOR)
	assert.Equal(t, int(result.header.PID), result.cmd.Process.Pid)
	assert.Equal(t, byte2IPv4(result.body.DstIP), "10.0.1.1")
}

func TestAuditContainer(t *testing.T) {
	fixture := "../../../testdata/container.yml"
	args := []string{"-c", "/usr/bin/docker run --rm curlimages/curl@sha256:347bf0095334e390673f532456a60bea7070ef63f2ca02168fee46b867a51aa8 https://10.0.1.1"}
	result := runAuditWithOnce(fixture, "/bin/bash", args...)

	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("can not get hostname: %s", err)
	}

	assert.Nil(t, result.err)
	assert.Equal(t, result.body.ActionResult(), ACTION_BLOCKED)
	assert.Equal(t, byte2IPv4(result.body.DstIP), "10.0.1.1")
	assert.Equal(t, len(nodename2string(result.header.Nodename)), 12)
	assert.NotEqual(t, nodename2string(result.header.Nodename), hostname)
}

func TestAuditContainerDoNotCaptureHostEvents(t *testing.T) {
	fixture := "../../../testdata/container.yml"
	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	config := loadFixtureConfig(fixture)
	mgr := createManager(config)
	eventsChannel := make(chan []byte)

	mgr.Start(eventsChannel)

	cmd := exec.Command("curl", "https://10.0.1.1")
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	go func() {
		eventBytes := <-eventsChannel
		fmt.Printf("%#v", eventBytes)
		done <- true
	}()

	// If an event is triggered on the host side and no event can be captured within the specified time, it is assumed that only the container's events are being captured
	// Unstable testing in an environment with other containers running.
	// If there's a better way, I'll replace it.
	select {
	case <-timeout:
	case <-done:
		t.Fatal("Got host events. Expect capture only container's event.")
	}
}

func runAuditWithOnce(configPath, execCmd string, execArgs ...string) auditResult {
	config := loadFixtureConfig(configPath)
	mgr := createManager(config)

	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	cmd := exec.Command(execCmd, execArgs...)
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	eventBytes := <-eventsChannel
	header, body, err := parseEvent(eventBytes)
	return auditResult{
		header: header,
		body:   body,
		cmd:    cmd,
		err:    err,
	}
}

func loadFixtureConfig(path string) *config.Config {
	conf, err := config.NewConfig(path)
	if err != nil {
		panic(err)
	}
	return conf
}

func createManager(conf *config.Config) Manager {
	mod, err := setupBPFProgram()
	if err != nil {
		panic(err)
	}

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	err = mgr.SetConfig()
	if err != nil {
		panic(err)
	}

	return mgr
}
