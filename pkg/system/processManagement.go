package system

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// processMonitor watches for a process to exit and returns the exit code on the immediately returned channel.
func processMonitor(p *os.Process) chan int {
	c := make(chan int, 1)

	go func(p *os.Process, c chan int) {
		if p == nil {
			log.Errorln("Attempted to monitor a process for run duration, but the passed process was nil.")
			c <- 255
			close(c)
			return
		}
		state, err := p.Wait()
		if err != nil {
			log.Errorln("Failed to wait for process to exit with error:", err)
			c <- 255
		}
		c <- state.ExitCode()
		close(c)
	}(p, c)
	return c
}

// killProcessAfterDuration kills a process after a duration of time has passed to ensure it does not
// run too long.  Specifically, this sends a shutdown signal of os.Kill.
func killProcessAfterDuration(p *os.Process, d time.Duration) {

	// check if the passed process is nil
	if p == nil {
		log.Errorln("Attempted to monitor and kill a process after duration, but the passed process was nil.  The passed duration for killing was:", d)
		return
	}

	// either the process will exit or it will run too long
	select {
	case <-time.After(d):
		// timeout
		err := p.Signal(os.Kill)
		log.Errorln("Error when trying to kill process after running too long:", err)
	case exitCode := <-processMonitor(p):
		// process completed
		log.Debugln("killProcessAfterDuration: process exited with code:", exitCode)
	}
}
