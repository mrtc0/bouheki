//go:build integration
// +build integration

package mount

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"testing"
	"time"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestAudit_Mount(t *testing.T) {
	be_blocked_path := "/var/run/docker.sock"
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	conf := config.DefaultConfig()
	conf.RestrictedMountConfig.Target = "container"
	conf.RestrictedMountConfig.Mode = "block"
	conf.RestrictedMountConfig.DenySourcePath = []string{be_blocked_path}
	eventsChannel := make(chan []byte)

	mountOption := fmt.Sprintf("%s:%s", be_blocked_path, be_blocked_path)
	command := []string{"docker", "run", "--rm", "-v", mountOption, "alpine:3.15.0", "pwd"}

	auditManager := runAuditWithOnce(conf, command, eventsChannel)
	defer auditManager.manager.Stop()
	defer auditManager.manager.mod.Close()

	go func() {
		for {
			eventBytes := <-eventsChannel

			event, err := parseEvent(eventBytes)
			assert.Nil(t, err)

			if be_blocked_path == pathToString(event.MountSourcePath) {
				assert.Equal(t, int32(-1), event.Ret)
				assert.Equal(t, be_blocked_path, pathToString(event.MountSourcePath))
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

func TestRunAudit_Conf(t *testing.T) {
	config := config.DefaultConfig()
	config.RestrictedMountConfig.Enable = false
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	assert.Nil(t, RunAudit(ctx, &wg, config))
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
