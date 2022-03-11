//go:build integration
// +build integration

package fileaccess

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mrtc0/bouheki/pkg/audit/helpers"
	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestAudit_DenyAccess(t *testing.T) {
	be_blocked_path := "/etc/hosts"
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	conf := config.DefaultConfig()
	conf.RestrictedFileAccess.Mode = "block"
	conf.RestrictedFileAccess.Target = "host"
	conf.RestrictedFileAccess.Deny = []string{be_blocked_path}
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(conf, []string{"cat", be_blocked_path}, eventsChannel)
	defer auditManager.manager.Stop()
	defer auditManager.manager.mod.Close()

	go func() {
		for {
			eventBytes := <-eventsChannel

			event, err := parseEvent(eventBytes)
			assert.Nil(t, err)

			if be_blocked_path == pathToString(event.Path) {
				assert.Equal(t, int32(-1), event.Ret)
				assert.Equal(t, auditManager.cmd.Process.Pid, int(event.PID))
				assert.Equal(t, be_blocked_path, pathToString(event.Path))
				done <- true
				break
			}
		}
	}()

	select {
	case <-timeout:
		t.Fatalf("Timeout. %s has not accessed.", be_blocked_path)
	case <-done:
		t.Log("OK")
	}

	err := exec.Command("cat", "/etc/passwd").Run()
	assert.Nil(t, err)
}

func TestAudit_Container(t *testing.T) {
	out, _ := exec.Command("bpftool", "map", "list").Output()
	fmt.Println(string(out))
	be_blocked_path := "/root/.bashrc"
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	conf := config.DefaultConfig()
	conf.RestrictedFileAccess.Mode = "block"
	conf.RestrictedFileAccess.Target = "container"
	conf.RestrictedFileAccess.Deny = []string{be_blocked_path}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("can not get hostname: %s", err)
	}

	commands := []string{
		"/bin/bash",
		"-c",
		fmt.Sprintf("/usr/bin/docker run --rm ubuntu:latest cat %s", be_blocked_path),
	}
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(conf, commands, eventsChannel)
	defer auditManager.manager.Stop()
	defer auditManager.manager.mod.Close()

	go func() {
		for {
			eventBytes := <-eventsChannel

			event, err := parseEvent(eventBytes)
			assert.Nil(t, err)

			if be_blocked_path == pathToString(event.Path) {
				assert.Equal(t, int32(-1), event.Ret)
				assert.NotEqual(t, helpers.NodenameToString(event.Nodename), hostname)
				assert.Equal(t, be_blocked_path, pathToString(event.Path))
				done <- true
				break
			}
		}
	}()

	select {
	case <-timeout:
		t.Fatalf("Timeout. %s has not accessed.", be_blocked_path)
	case <-done:
		t.Log("OK")
	}
}

type TestAuditManager struct {
	manager Manager
	cmd     *exec.Cmd
}

func runAuditWithOnce(conf *config.Config, execCmd []string, eventsChannel chan []byte) TestAuditManager {
	mgr := createManager(conf)
	mgr.Attach()
	lostChannel := make(chan uint64)
	mgr.Start(eventsChannel, lostChannel)

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
