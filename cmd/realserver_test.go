package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
)

type mockWorker struct {
	started chan bool
}

func (m *mockWorker) Start() error {
	select {
	case m.started <- true:
	default:
	}
	return nil
}
func (m *mockWorker) Stop() error { return nil }
func (m *mockWorker) drain() {
	for len(m.started) > 0 {
		<-m.started
	}
}

func TestBlockForever(t *testing.T) {
	ctx, cxl := context.WithTimeout(context.Background(), 3000*time.Millisecond)
	defer cxl()

	logger := logrus.New()
	maxTries := 2
	worker := &mockWorker{make(chan bool)}

	ln, port := testListener()
	fmt.Println("got port ", port)

	// base case
	worker.drain()
	go blockForever(ctx, worker, port, maxTries, logger)
	select {
	case <-ctx.Done():
		// pass
	case <-worker.started:
		// fail
		t.Fatal("unexpected start")
	}

	//  change the port to something bogus
	ctx, cxl = context.WithTimeout(context.Background(), 3000*time.Millisecond)
	defer cxl()
	worker.drain()
	go blockForever(ctx, worker, 0, maxTries, logger)
	select {
	case <-ctx.Done():
		t.Fatal("worker didn't start before context expired")
	case <-worker.started:
		// pass
	}

	// test to ensure that the server starts up after N retries
	maxTries = 4
	ctx, cxl = context.WithTimeout(context.Background(), 6000*time.Millisecond)
	defer cxl()
	worker.drain()
	go blockForever(ctx, worker, port, maxTries, logger)
	select {
	case <-time.After(500 * time.Millisecond):
		fmt.Println("closed listener")
		ln.Close()
	case <-ctx.Done():
		// pass
	}

	// this timer is one less thn max tries. it ifs ticker goes off, that
	// indicates that the server started itself after the full wait time
	// elapsed, which is a successful result. if the timer does not expire,
	// that means that the restart completed before the full wait time
	td := (time.Duration(maxTries) * time.Second) - (1 * time.Second)
	timer := time.NewTimer(td)
	select {
	case <-worker.started:
		// pass
	case <-ctx.Done():
		t.Fatal("context expired before worker started")
	}
	// need to make sure that the retry actually took the full amount of time
	select {
	case <-timer.C:
		// pass
	default:
		t.Fatal("worker started before full failover timeout elapsed")
	}

}

func testListener() (net.Listener, int) {
	addr := fmt.Sprintf("localhost:%d", 0)
	logger.Debugf("listening forever on %s", addr)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(1)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			<-time.After(50 * time.Millisecond)
			conn.Close()
		}
	}()
	i, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])
	return ln, i
}
