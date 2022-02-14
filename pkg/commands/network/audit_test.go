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

type TestAuditManager struct {
	manager Manager
	cmd     *exec.Cmd
}

func TestAuditBlockMode(t *testing.T) {
	fixture := "../../../testdata/block.yml"
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(fixture, []string{"curl", "http://93.184.216.34"}, eventsChannel)
	eventBytes := <-eventsChannel
	header, body, err := parseEvent(eventBytes)

	assert.Nil(t, err)
	assert.Equal(t, ACTION_BLOCKED, body.ActionResult())
	assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
	assert.Equal(t, "93.184.216.34", byte2IPv4(body.DstIP))

	err = exec.Command("curl", "https://google.com").Run()
	assert.Nil(t, err)

	err = exec.Command("curl", "http://93.184.216.34").Run()
	assert.NotNil(t, err)

	auditManager.manager.mod.Close()
}

func TestAuditMonitorMode(t *testing.T) {
	fixture := "../../../testdata/monitor.yml"
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(fixture, []string{"curl", "http://93.184.216.34"}, eventsChannel)
	eventBytes := <-eventsChannel
	header, body, err := parseEvent(eventBytes)

	assert.Nil(t, err)
	assert.Equal(t, ACTION_MONITOR, body.ActionResult())
	assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
	assert.Equal(t, "93.184.216.34", byte2IPv4(body.DstIP))

	auditManager.manager.mod.Close()
}

func TestCanCommunicateWithRestrictedCommand(t *testing.T) {
	fixture := "../../../testdata/command_allow.yml"
	config := loadFixtureConfig(fixture)
	mgr := createManager(config)

	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	err := exec.Command("curl", "http://93.184.216.34").Run()
	assert.Nil(t, err)

	mgr.mod.Close()
}

func TestRestrictedCommand(t *testing.T) {
	fixture := "../../../testdata/command_deny.yml"
	config := loadFixtureConfig(fixture)
	mgr := createManager(config)

	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	err := exec.Command("curl", "http://example.com").Run()
	assert.NotNil(t, err)

	cmd := exec.Command("wget", "-t", "1", "http://example.com", "-O", "/dev/null")
	err = cmd.Run()

	fmt.Printf("%#v %#v", cmd.Stdout, err)
	assert.Nil(t, err)

	mgr.mod.Close()
}

func TestAuditContainerBlock(t *testing.T) {
	fixture := "../../../testdata/container.yml"
	eventsChannel := make(chan []byte)
	commands := []string{"/bin/bash", "-c", "/usr/bin/docker run --rm curlimages/curl@sha256:347bf0095334e390673f532456a60bea7070ef63f2ca02168fee46b867a51aa8 http://93.184.216.34"}
	auditManager := runAuditWithOnce(fixture, commands, eventsChannel)
	eventBytes := <-eventsChannel
	header, body, err := parseEvent(eventBytes)

	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("can not get hostname: %s", err)
	}

	assert.Nil(t, err)
	assert.Equal(t, body.ActionResult(), ACTION_BLOCKED)
	assert.Equal(t, byte2IPv4(body.DstIP), "93.184.216.34")
	assert.Equal(t, len(nodename2string(header.Nodename)), 12)
	assert.NotEqual(t, nodename2string(header.Nodename), hostname)

	auditManager.manager.mod.Close()
}

func TestAuditContainerDoNotCaptureHostEvents(t *testing.T) {
	fixture := "../../../testdata/container.yml"
	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	config := loadFixtureConfig(fixture)
	mgr := createManager(config)
	eventsChannel := make(chan []byte)

	mgr.Start(eventsChannel)

	cmd := exec.Command("curl", "http://93.184.216.34")
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

	mgr.mod.Close()
}

func runAuditWithOnce(configPath string, execCmd []string, eventsChannel chan []byte) TestAuditManager {
	config := loadFixtureConfig(configPath)
	mgr := createManager(config)

	mgr.Start(eventsChannel)

	cmd := exec.Command(execCmd[0], execCmd[1:]...)
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	return TestAuditManager{
		manager: mgr,
		cmd:     cmd,
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
