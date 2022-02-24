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

func runPipeCommands(ctx context.Context, commandA []string, commandB []string) (*bytes.Buffer, error) {

	// create a context timeout for our processes
	ctx, ctxCancel := context.WithTimeout(ctx, time.Second*30)
	defer ctxCancel()

	// create two processes to run
	commandAArgs := commandA[1:]
	commandBArgs := commandB[1:]
	c1 := exec.CommandContext(ctx, commandA[0], commandAArgs...)
	c2 := exec.CommandContext(ctx, commandB[0], commandBArgs...)

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

	return outputBuf, nil
}

func run() ([]string, error) {
	commandA := []string{"cat", "link-output.txt"}
	commandB := []string{"grep", "-B", "2", "dummy"}

	outputBuf, err := runPipeCommands(context.TODO(), commandA, commandB)
	if err != nil {
		log.Errorln("ipManager: error running commands:", err)
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

	return iFaces, nil
}
