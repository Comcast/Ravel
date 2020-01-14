package main

import (
	"io/ioutil"
	"testing"
)

// TestNewIPVSConfig ensures that all the default values are set for a new config
func TestNewIPVSConfig(t *testing.T) {
	// simple instantiation to test that defaults are set
	config, err := NewIPVSConfig([]string{})
	if err != nil {
		t.Fatal("saw error instantiating IPVSConfig", err)
	}

	// non-exhaustive list to check some of our defaults
	if config.AmDroprate != "10" {
		t.Fatalf("config did not correctly set default; expected 10, saw %s", config.AmDroprate)
	}

	if config.AMemThresh != "1024" {
		t.Fatalf("config did not correctly set default; expected 1024, saw %s", config.AMemThresh)
	}

	if config.IgnoreTunneled != "1" {
		t.Fatalf("config did not correctly set default; expected 1, saw %s", config.IgnoreTunneled)
	}

	if config.SyncQlenMax != "1028304" {
		t.Fatalf("config did not correctly set default; expected 1028304, saw %s", config.SyncQlenMax)
	}

	if config.PmtuDisc != "1" {
		t.Fatalf("config did not correctly set default; expected 1, saw %s", config.PmtuDisc)
	}

	if config.ScheduleIcmp != "0" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.ScheduleIcmp)
	}

	// test setting defaults via strings to simulate passing in via CLI
	cliParams := []string{"backup_only=500", "conntrack=500", "expire_quiescent_template=500", "pmtu_disc=500", "sync_ports=500", "sync_sock_size=500"}
	config, err = NewIPVSConfig(cliParams)
	if err != nil {
		t.Fatal("saw error instantiating IPVSConfig", err)
	}

	if config.BackupOnly != "500" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.BackupOnly)
	}

	if config.Conntrack != "500" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.Conntrack)
	}

	if config.ExpireQuiescentTemplate != "500" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.ExpireQuiescentTemplate)
	}

	if config.PmtuDisc != "500" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.PmtuDisc)
	}

	if config.SyncPorts != "500" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.SyncPorts)
	}

	if config.SyncSockSize != "500" {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", config.SyncSockSize)
	}

	// verify an error is produced for a bogus tag and that we don't panic
	cliParams = []string{"bogus-tag"}
	_, err = NewIPVSConfig(cliParams)
	if err == nil {
		t.Fatal("should have seen an error for a bogus tag, saw <nil>")
	}

	// verify an error is produced for a bogus tag that is correctly formatted
	cliParams = []string{"bogus-tag=1"}
	_, err = NewIPVSConfig(cliParams)
	if err == nil {
		t.Fatal("should have seen an error for a bogus tag, saw <nil>")
	}
}

// TestWriteToDisk for this to succeed, the directory structure + files need to exist already. Mac users need to do this before expecting this test to work
// you also need to run this test with sudo
func TestWriteToDisk(t *testing.T) {
	cliParams := []string{"backup_only=500", "conntrack=500", "expire_quiescent_template=500", "pmtu_disc=500", "sync_ports=500", "sync_sock_size=500"}
	config, err := NewIPVSConfig(cliParams)
	if err != nil {
		t.Fatal("saw error instantiating IPVSConfig", err)
	}

	// verify that fields without tags don't break stuff
	config.ColocationMode = "anything"

	err = config.WriteToNode()
	if err != nil {
		t.Fatal("saw error writing values:", err)
	}

	// read some values
	dat, err := ioutil.ReadFile("/proc/sys/net/ipv4/vs/backup_only")
	if err != nil {
		t.Fatal("saw error reading from file:", err)
	}

	if string(dat) != "500" {
		t.Fatalf("passed parameter was not actually written to file. expected 500, saw %s", string(dat))
	}

	// read some values
	dat, err = ioutil.ReadFile("/proc/sys/net/ipv4/vs/expire_quiescent_template")
	if err != nil {
		t.Fatal("saw error reading from file:", err)
	}

	if string(dat) != "500" {
		t.Fatalf("passed parameter was not actually written to file. expected 500, saw %s", string(dat))
	}

	// read some values
	dat, err = ioutil.ReadFile("/proc/sys/net/ipv4/vs/sync_qlen_max")
	if err != nil {
		t.Fatal("saw error reading from file:", err)
	}

	if string(dat) != "1028304" {
		t.Fatalf("default from tag was not actually written to file. expected 1028304, saw %s", string(dat))
	}

}
