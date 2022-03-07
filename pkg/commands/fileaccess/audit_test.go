package fileaccess

import (
	"os/exec"
	"testing"
	"time"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestAudit_DenyAccess(t *testing.T) {
	be_blocked_path := "/etc/hosts"
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	conf := config.DefaultConfig()
	conf.RestrictedFileAccess.Deny = []string{be_blocked_path}
	eventsChannel := make(chan []byte)
	auditManager := runAuditWithOnce(conf, []string{"cat", be_blocked_path}, eventsChannel)

	go func() {
		for {
			eventBytes := <-eventsChannel

			event, err := parseEvent(eventBytes)
			assert.Nil(t, err)

			if be_blocked_path == path2string(event.Path) {
				assert.Equal(t, auditManager.cmd.Process.Pid, int(event.PID))
				assert.Equal(t, be_blocked_path, path2string(event.Path))
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

type TestAuditManager struct {
	manager Manager
	cmd     *exec.Cmd
}

func runAuditWithOnce(conf *config.Config, execCmd []string, eventsChannel chan []byte) TestAuditManager {
	mgr := createManager(conf)
	mgr.Attach()
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
