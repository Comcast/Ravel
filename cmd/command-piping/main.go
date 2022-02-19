package main

import (
	"bytes"
	"context"
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

	// pipe the first process to the second process
	var err error
	c2.Stdin, err = c1.StdoutPipe()
	if err != nil {
		panic(err)
	}

	// make an output buffer and attach it to the output of command 2
	outputBuf := bytes.NewBuffer([]byte{})
	c2.Stdout = outputBuf

	// start the second process that will read from the first process
	err = c2.Start()
	if err != nil {
		panic(err)
	}

	// start the first that pipes to the second and wait for it to finish
	err = c1.Run()
	if err != nil {
		panic(err)
	}

	// wait for the second process to finish
	err = c2.Wait()
	if err != nil {
		panic(err)
	}

	// list over the interfaces parsed from CLI output and append them into a slice
	iFaces := []string{}
	b2SplFromLines := strings.Split(outputBuf.String(), "\n")
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
