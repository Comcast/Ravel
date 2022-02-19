package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {
	results, err := run()
	log.Println("results:", results)
	log.Println("error:", err)
}

func run() ([]string, error) {

	// create a context timeout for our processes
	ctx, ctxCancel := context.WithTimeout(context.TODO(), time.Second*10)
	defer ctxCancel()

	// create two processes to run
	c1 := exec.CommandContext(ctx, "cat", "link-output.txt")
	c2 := exec.CommandContext(ctx, "grep", "-B", "2", "dummy")

	// map the processes together with a pipe
	var err error
	c2.Stdin, err = c1.StdoutPipe()
	if err != nil {
		return []string{}, fmt.Errorf("ipManager: error creating pipe from process 1 to 2: %w", err)
	}

	// make an output buffer and attach it to the output of command 2
	b2 := bytes.NewBuffer([]byte{})
	c2.Stdout = b2

	// start the main processes
	log.Debugln("ipManager: starting process 1 (ip -details link show)")
	err = c1.Run()
	if err != nil {
		return []string{}, fmt.Errorf("ipManager: error running ip to retrieve interfaces: %w", err)
	}

	// start the grep command
	log.Debugln("ipManager: starting process 2 (grep -B 2 dummy)")
	err = c2.Run()
	if err != nil {
		if !strings.Contains(err.Error(), "exit status 1") {
			log.Debugln("ipManager: process 2 completed with error:", err)
			// if golang accepts empty input to a pipe (in our case, no ifaces)
			// it errs exit 1. Return no ifaces
			return []string{}, err
		}
		log.Warningln("ipManager: found no dummy interfaces with exit message:", err)
		return []string{}, nil
	}

	log.Debugln("ipManager: got", b2.Len(), "bytes from grep output")

	// list over the interfaces parsed from CLI output and append them into a slice
	iFaces := []string{}
	b2SplFromLines := strings.Split(b2.String(), "\n")
	for _, l := range b2SplFromLines {
		if strings.Contains(l, "mtu") {
			awked := strings.Split(l, " ")
			if len(awked) >= 2 {
				iFace := strings.Replace(awked[1], ":", "", 1)
				iFaces = append(iFaces, iFace)
			}
		}
	}

	log.Debugln("ipManager: parsed ", len(iFaces), "interfaces")
	log.Debugln("ipManager: retrieveDummyInterfaces completed")

	return iFaces, nil
}
