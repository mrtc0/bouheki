package network

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

type TestAuditManager struct {
	manager Manager
	cmd     *exec.Cmd
}

func composeUp() error {
	_, err := exec.Command("docker-compose", "-f", "../../../testdata/docker-compose.yml", "up", "-d").Output()
	if err != nil {
		return err
	}

	return nil
}

func composeDown() {
	exec.Command("docker-compose", "-f", "../../../testdata/docker-compose.yml", "down").Run()
}

func TestMain(m *testing.M) {
	err := composeUp()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	r := m.Run()
	composeDown()
	os.Exit(r)
}

func TestActionResultForV4(t *testing.T) {
	tests := []struct {
		name     string
		input    detectEventIPv4
		expected string
	}{
		{
			name: "Returns 'BLOCKED' if value `0` is returned",
			input: detectEventIPv4{
				SrcIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_BLOCKED,
				SockType:     TCP,
			},
			expected: ACTION_BLOCKED_STRING,
		},
		{
			name: "Returns 'MONITOR' if value `1` is returned",
			input: detectEventIPv4{
				SrcIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_MONITOR,
				SockType:     TCP,
			},
			expected: ACTION_MONITOR_STRING,
		},
		{
			name: "Returns 'unknown' if undefined value is returned.",
			input: detectEventIPv4{
				SrcIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       10,
				SockType:     TCP,
			},
			expected: ACTION_UNKNOWN_STRING,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.input.ActionResult())
		})
	}
}

func TestActionResultForV6(t *testing.T) {
	tests := []struct {
		name     string
		input    detectEventIPv6
		expected string
	}{
		{
			name: "Returns 'BLOCKED' iff value `0` is returned",
			input: detectEventIPv6{
				SrcIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_BLOCKED,
				SockType:     TCP,
			},
			expected: ACTION_BLOCKED_STRING,
		},
		{
			name: "Returns 'MONITOR' iff value `1` is returned",
			input: detectEventIPv6{
				SrcIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_MONITOR,
				SockType:     TCP,
			},
			expected: ACTION_MONITOR_STRING,
		},
		{
			name: "Returns 'unknown' if undefined value is returned.",
			input: detectEventIPv6{
				SrcIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       10,
				SockType:     TCP,
			},
			expected: ACTION_UNKNOWN_STRING,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.input.ActionResult())
		})
	}
}

func TestAuditBlockModeV4(t *testing.T) {
	fixture := "../../../testdata/block_v4.yml"
	be_blocked_addr := "10.254.249.3"
	be_allowed_addr := "10.254.249.4"
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(fixture, []string{"curl", fmt.Sprintf("http://%s", be_blocked_addr)}, eventsChannel)
	eventBytes := <-eventsChannel
	header, rawBody, err := parseEvent(eventBytes)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, header.EventType)

	body := rawBody.(detectEventIPv4)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
	assert.Equal(t, be_blocked_addr, byte2IPv4(body.DstIP))

	err = exec.Command("curl", fmt.Sprintf("http://%s", be_allowed_addr)).Run()
	assert.Nil(t, err)

	err = exec.Command("curl", fmt.Sprintf("http://%s", be_blocked_addr)).Run()
	assert.NotNil(t, err)

	auditManager.manager.mod.Close()
}

func TestAuditBlockModeV6(t *testing.T) {
	fixture := "../../../testdata/block_v6.yml"
	eventsChannel := make(chan []byte)
	be_blocked_addr := "2001:3984:3989::3"
	be_allowed_addr := "2001:3984:3989::4"
	auditManager := runAuditWithOnce(fixture, []string{"curl", "-6", fmt.Sprintf("http://[%s]", be_blocked_addr)}, eventsChannel)
	eventBytes := <-eventsChannel
	header, rawBody, err := parseEvent(eventBytes)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV6, header.EventType)

	body := rawBody.(detectEventIPv6)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
	assert.Equal(t, bytes.Equal(net.ParseIP(be_blocked_addr), net.ParseIP(byte2IPv6(body.DstIP))), true)

	err = exec.Command("curl", "-6", fmt.Sprintf("http://[%s]", be_allowed_addr)).Run()
	assert.Nil(t, err)

	err = exec.Command("curl", "-6", fmt.Sprintf("http://[%s]", be_blocked_addr)).Run()
	assert.NotNil(t, err)

	auditManager.manager.mod.Close()
}

func TestAuditBlockModeDomainV4(t *testing.T) {
  fixture := "../../../testdata/block_domain_v4.yml"
  eventsChannel := make(chan []byte)
  be_blocked_domain := "nginx-1.v4"
  be_blocked_ip     := "10.254.249.3"
  be_allowed_domain := "nginx-2.v4"
  auditManager := runAuditWithOnce(fixture, []string{"curl", fmt.Sprintf("http://%s", be_blocked_domain)}, eventsChannel)
  eventBytes := <-eventsChannel
  header, rawBody, err := parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV4, header.EventType)

  body := rawBody.(detectEventIPv4)

  assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, bytes.Equal(net.ParseIP(be_blocked_ip), net.ParseIP(byte2IPv4(body.DstIP))), true)

  err = exec.Command("curl", fmt.Sprintf("http://%s", be_allowed_domain)).Run()
  assert.Nil(t, err)

  err = exec.Command("curl", fmt.Sprintf("http://%s", be_blocked_domain)).Run()
  assert.NotNil(t, err)

  auditManager.manager.mod.Close()
}

func TestAuditBlockModeDomainV6(t *testing.T) {
  fixture := "../../../testdata/block_domain_v6.yml"
  eventsChannel := make(chan []byte)
  be_blocked_domain := "nginx-1.v6"
  be_blocked_ip     := "2001:3984:3989::3"
  be_allowed_domain := "nginx-2.v6"
  auditManager := runAuditWithOnce(fixture, []string{"curl", "-6", fmt.Sprintf("http://%s", be_blocked_domain)}, eventsChannel)
  eventBytes := <-eventsChannel
  header, rawBody, err := parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV6, header.EventType)

  body := rawBody.(detectEventIPv6)

  assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, bytes.Equal(net.ParseIP(be_blocked_ip), net.ParseIP(byte2IPv6(body.DstIP))), true)

  err = exec.Command("curl", "-6", fmt.Sprintf("http://%s", be_allowed_domain)).Run()
  assert.Nil(t, err)

  err = exec.Command("curl", "-6", fmt.Sprintf("http://%s", be_blocked_domain)).Run()
  assert.NotNil(t, err)

  auditManager.manager.mod.Close()
}

func TestAuditDomainUpdateV4(t *testing.T) {
  fixture := "../../../testdata/block_domain_v4.yml"
  be_blocked_ip := "10.254.249.3"
  be_allowed_ip := "10.254.249.4"
  eventsChannel := make(chan []byte)
  auditManager := runAuditWithOnce(fixture, []string{"curl", fmt.Sprintf("http://%s", be_blocked_ip)}, eventsChannel) 
  eventBytes := <-eventsChannel
  header, rawBody, err := parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV4, header.EventType)

  body := rawBody.(detectEventIPv4)

  assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, bytes.Equal(net.ParseIP(be_blocked_ip), net.ParseIP(byte2IPv4(body.DstIP))), true)

  err = exec.Command("curl", fmt.Sprintf("http://%s", be_allowed_ip)).Run()
  assert.Nil(t, err)

  exec.Command("sed", "-i", "'s/249\\.3/249\\.4/g'", "../../../testdata/hosts").Run()
  err = auditManager.manager.setDeniedDomainList()
  assert.Nil(t, err)
  err = auditManager.manager.setAllowedDomainList()
  assert.Nil(t, err)

  auditManager = runAuditWithOnce(fixture, []string{"curl", fmt.Sprintf("http://%s", be_allowed_ip)}, eventsChannel) 
  eventBytes = <-eventsChannel
  header, rawBody, err = parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV4, header.EventType)

  body = rawBody.(detectEventIPv4)

  assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, bytes.Equal(net.ParseIP(be_allowed_ip), net.ParseIP(byte2IPv4(body.DstIP))), true)
  
  auditManager.manager.mod.Close()

  defer exec.Command("cp", "../../../testdata/hosts.bk", "../../../testdata/hosts").Run()
}

func TestAuditDomainUpdateV6(t *testing.T) {
  fixture := "../../../testdata/block_domain_v6.yml"
  be_blocked_ip := "2001:3984:3989::3"
  be_allowed_ip := "2001:3984:3989::4"
  eventsChannel := make(chan []byte)
  auditManager := runAuditWithOnce(fixture, []string{"curl", "-6", fmt.Sprintf("http://[%s]", be_blocked_ip)}, eventsChannel) 
  eventBytes := <-eventsChannel
  header, rawBody, err := parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV6, header.EventType)

  body := rawBody.(detectEventIPv6)

  assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, bytes.Equal(net.ParseIP(be_blocked_ip), net.ParseIP(byte2IPv6(body.DstIP))), true)

  err = exec.Command("curl", "-6", fmt.Sprintf("http://[%s]", be_allowed_ip)).Run()
  assert.Nil(t, err)

  exec.Command("sed", "-i", "'s/::3/::4/g'", "../../../testdata/hosts").Run()
  err = auditManager.manager.setDeniedDomainList()
  assert.Nil(t, err)
  err = auditManager.manager.setAllowedDomainList()
  assert.Nil(t, err)

  auditManager = runAuditWithOnce(fixture, []string{"curl", "-6", fmt.Sprintf("http://[%s]", be_allowed_ip)}, eventsChannel) 
  eventBytes = <-eventsChannel
  header, rawBody, err = parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV6, header.EventType)

  body = rawBody.(detectEventIPv6)

  assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, bytes.Equal(net.ParseIP(be_allowed_ip), net.ParseIP(byte2IPv6(body.DstIP))), true)
  
  auditManager.manager.mod.Close()

  defer exec.Command("cp", "../../../testdata/hosts.bk", "../../../testdata/hosts").Run()
}

func TestAuditMonitorModeDomainV4(t *testing.T) {
  fixture := "../../../testdata/monitor_domain_v4.yml"
  eventsChannel := make(chan []byte)
  be_monitord_addr := "10.254.249.3"
  be_monitord_domain := "nginx-1.v4"
  auditManager := runAuditWithOnce(fixture, []string{"curl", fmt.Sprintf("http://%s", be_monitord_domain)}, eventsChannel)
  eventBytes := <-eventsChannel
  header, rawBody, err := parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV4, header.EventType)

  body := rawBody.(detectEventIPv4)

  assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, be_monitord_addr, byte2IPv4(body.DstIP))

  auditManager.manager.mod.Close()
}

func TestAuditMonitorModeDomainV6(t *testing.T) {
  fixture := "../../../testdata/monitor_domain_v6.yml"
  eventsChannel := make(chan []byte)
  be_monitord_addr := "2001:3984:3989:0000:0000:0000:0000:0003"
  be_monitord_domain := "nginx-1.v6"
  auditManager := runAuditWithOnce(fixture, []string{"curl", "-6", fmt.Sprintf("http://%s", be_monitord_domain)}, eventsChannel)
  eventBytes := <-eventsChannel
  header, rawBody, err := parseEvent(eventBytes)
  assert.Nil(t, err)

  assert.Equal(t, BLOCKED_IPV6, header.EventType)

  body := rawBody.(detectEventIPv6)

  assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
  assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
  assert.Equal(t, be_monitord_addr, byte2IPv6(body.DstIP))

  auditManager.manager.mod.Close()
}

func TestAuditMonitorModeV4(t *testing.T) {
	fixture := "../../../testdata/monitor_v4.yml"
	eventsChannel := make(chan []byte)
	be_monitord_addr := "10.254.249.3"
	auditManager := runAuditWithOnce(fixture, []string{"curl", fmt.Sprintf("http://%s", be_monitord_addr)}, eventsChannel)
	eventBytes := <-eventsChannel
	header, rawBody, err := parseEvent(eventBytes)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, header.EventType)

	body := rawBody.(detectEventIPv4)

	assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
	assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
	assert.Equal(t, be_monitord_addr, byte2IPv4(body.DstIP))

	auditManager.manager.mod.Close()
}

func TestAuditMonitorModeV6(t *testing.T) {
	fixture := "../../../testdata/monitor_v6.yml"
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(fixture, []string{"curl", "-6", "http://[2606:2800:220:1:248:1893:25c8:1946]"}, eventsChannel)
	eventBytes := <-eventsChannel
	header, rawBody, err := parseEvent(eventBytes)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV6, header.EventType)

	body := rawBody.(detectEventIPv6)

	assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
	assert.Equal(t, auditManager.cmd.Process.Pid, int(header.PID))
	assert.Equal(t, "2606:2800:0220:0001:0248:1893:25c8:1946", byte2IPv6(body.DstIP))

	auditManager.manager.mod.Close()
}

func TestCanCommunicateWithRestrictedCommand(t *testing.T) {
	fixture := "../../../testdata/command_allow.yml"
	config := loadFixtureConfig(fixture)
	be_blocked_addr := "10.254.249.3"
	mgr := createManager(config)

	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	err := exec.Command("curl", fmt.Sprintf("http://%s", be_blocked_addr)).Run()
	assert.Nil(t, err)

	mgr.mod.Close()
}

func TestRestrictedCommand(t *testing.T) {
	fixture := "../../../testdata/command_deny.yml"
	config := loadFixtureConfig(fixture)
	be_blocked_addr := "10.254.249.3"
	mgr := createManager(config)

	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	err := exec.Command("curl", fmt.Sprintf("http://%s", be_blocked_addr)).Run()
	assert.NotNil(t, err)

	cmd := exec.Command("wget", "-t", "1", fmt.Sprintf("http://%s", be_blocked_addr), "-O", "/dev/null")
	err = cmd.Run()

	assert.Nil(t, err)

	mgr.mod.Close()
}

func TestAuditContainerBlock(t *testing.T) {
	fixture := "../../../testdata/container.yml"
	eventsChannel := make(chan []byte)
	be_blocked_addr := "10.254.249.3"
	commands := []string{
		"/bin/bash",
		"-c",
		fmt.Sprintf(
			"/usr/bin/docker run --rm curlimages/curl@sha256:347bf0095334e390673f532456a60bea7070ef63f2ca02168fee46b867a51aa8 http://%s",
			be_blocked_addr),
	}
	auditManager := runAuditWithOnce(fixture, commands, eventsChannel)
	eventBytes := <-eventsChannel
	header, rawBody, err := parseEvent(eventBytes)

	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("can not get hostname: %s", err)
	}

	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, header.EventType)

	body := rawBody.(detectEventIPv4)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, byte2IPv4(body.DstIP), be_blocked_addr)
	assert.Equal(t, len(nodename2string(header.Nodename)), 12)
	assert.NotEqual(t, nodename2string(header.Nodename), hostname)

	auditManager.manager.mod.Close()
}

func TestAuditContainerDoNotCaptureHostEvents(t *testing.T) {
	fixture := "../../../testdata/container.yml"
	be_blocked_addr := "10.254.249.3"
	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	config := loadFixtureConfig(fixture)
	mgr := createManager(config)
	eventsChannel := make(chan []byte)

	mgr.Start(eventsChannel)

	cmd := exec.Command("curl", fmt.Sprintf("http://%s", be_blocked_addr))
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	go func() {
		<-eventsChannel
		done <- true
	}()

	// If an event is triggered on the host side and no event can be captured within the specified time, it is assumed that only the container's events are being captured
	// Unstable testing in an environment with other containers running.
	// If there's a better way, I'll replace it.
	select {
	case <-timeout:
		t.Log("OK")
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
    cache: make(map[string][]DomainCache),
	}

	err = mgr.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return mgr
}
