package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// listenController is used by the realserver in order to determine whether it is colocated with a director.
// The kube director will listen on this port on localhost, cleaning up connections when it's done.
// This function will run until the program exits. it would be better served by a unix sock
func listenController(port int, cm *coordinationMetrics, logger logrus.FieldLogger) {
	addr := fmt.Sprintf("localhost:%d", port)
	logger.Debugf("listening forever on %s", addr)

	cm.Running(true)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// NOTE: If another program is listening on this port, this will result in a sort of infinite loop behavior as
		// the director process dies and comes back to life.
		//
		// Hard error. If the director can't listen on this port, it may indicate that another director is already running.
		// The behavior of the program is unspecified in this case, as the backend uses this port in order to determine
		// whether to operate normally, or to suspend operations whil colocated with a director. We exit.
		logger.Error(err)
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			cm.Check(false)
			continue
		}
		<-time.After(50 * time.Millisecond)
		cm.Check(true)
		conn.Close()
	}
}
