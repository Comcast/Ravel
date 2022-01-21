package main

import (
	"context"
	"log"

	"github.com/Comcast/Ravel/pkg/system"
	"github.com/sirupsen/logrus"
)

// retrieveDummyIFaces tries to greb for interfaces with 'dummy' in the output from 'ip -details link show'.
func main() {

	gateway := "10.131.153.65" // anvil2-net-test ravel node 10.131.153.73
	announce := 2              // anvil2-net-test ravel node 10.131.153.73
	loIgnore := 1              // anvil2-net-test ravel node 10.131.153.73
	logger := logrus.New()

	// make a new IPManager
	ipManager, err := system.NewIP(context.TODO(), "po0", gateway, announce, loIgnore, logger)
	if err != nil {
		log.Fatalln(err)
	}

	v4, v6, err := ipManager.Get()
	if err != nil {
		log.Fatalln(err)
	}

	for _, ip := range v4 {
		log.Println(ip)
	}
	for _, ip := range v6 {
		log.Println(ip)
	}
}
