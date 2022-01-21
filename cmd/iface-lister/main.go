package main

import (
	"bytes"
	"io"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// retrieveDummyIFaces tries to greb for interfaces with 'dummy' in the output from 'ip -details link show'.
func main() {

	// DEBUG
	// DEBUG
	// DEBUG
	log.SetLevel(log.DebugLevel) // TODO - remove

	log.Debugln("ipManager: Retrieving dummy interfaces. Waiting to lock interfaceMu...")

	// mutex this operation to prevent overlapping queries

	startTime := time.Now()

	// create two processes to run
	c1 := exec.Command("ip", "-details", "link", "show")
	log.Debugln("ipManager: c1 created")
	c2 := exec.Command("grep", "-B", "2", "dummy")
	log.Debugln("ipManager: c2 created")

	// map the processes together with a pipe
	r, w := io.Pipe()
	log.Debugln("ipManager: pipe created")
	c1.Stdout = w
	c2.Stdin = r
	defer r.Close()

	var b2 bytes.Buffer
	c2.Stdout = &b2

	// start the processes
	log.Debugln("ipManager: starting process 1 (ip -details link show)")
	err := c1.Start()
	if err != nil {
		log.Errorf("error retrieving interfaces: %v", err)
	}
	// go killProcessAfterDuration(c1.Process, time.Second*90)

	log.Debugln("ipManager: starting process 2 (grep -B 2 dummy)")
	err = c2.Start()
	if err != nil {
		log.Errorf("error retrieving interfaces: %v", err)
	}
	// go killProcessAfterDuration(c2.Process, time.Second*90)

	// wait for the processes to complete
	log.Debugln("ipManager: waiting for process 1 to complete")
	err = c1.Wait()
	if err != nil {
		log.Debugln("ipManager: process 1 completed with error:", err)
		log.Errorf("ipManager: ip command had error retrieving interfaces: %w", err)
	}
	log.Debugln("ipManager: process 1 completed")

	// close the pipe buffer after process 1 is complete
	err = w.Close()
	if err != nil {
		log.Errorf("ipManager: error closing pipe while retrieving interfaces: %w", err)
	}
	log.Debugln("ipManager: pipe closed")

	// wait for process 2 to complete
	log.Debugln("ipManager: waiting for process 2 to complete")
	err = c2.Wait()
	if err != nil {
		if !strings.Contains(err.Error(), "exit status 1") {
			log.Debugln("ipManager: process 2 completed with error:", err)
			// if golang accepts empty input to a pipe (in our case, no ifaces)
			// it errs exit 1. Return no ifaces
			log.Errorln(err)
		}
		log.Infoln("ipManager: found no dummy interfaces")
	}
	log.Debugln("ipManager: process 2 completed")

	// calculate how long this took to run
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	log.Debugln("ipManager: dummy interface retrieval took", duration)

	// list over the interfaces parsed from CLI output and glob them up
	iFaces := []string{}
	b2SplFromLines := strings.Split(string(b2.Bytes()), "\n")
	for _, l := range b2SplFromLines {
		if strings.Contains(l, "mtu") {
			awked := strings.Split(l, " ")
			if len(awked) >= 2 {
				iFace := strings.Replace(awked[1], ":", "", 1)

				// ensure that the interface has a ravel- prefix
				if !strings.HasPrefix(iFace, "ravel-") {
					continue
				}

				iFaces = append(iFaces, iFace)
			}
		}
	}

	log.Debugln("ipManager: parsed ", len(iFaces), "interfaces")
	log.Debugln("ipManager: retrieveDummyInterfaces completed")

}
