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
	value, err := config.GetSysCtlSetting("am_droprate")
	if value != "10" || err != nil {
		t.Fatalf("config did not correctly set default; expected 10, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("amemthresh")
	if value != "1024" || err != nil {
		t.Fatalf("config did not correctly set default; expected 1024, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("ignore_tunneled")
	if value != "1" || err != nil {
		t.Fatalf("config did not correctly set default; expected 1, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("sync_qlen_max")
	if value != "1028304" || err != nil {
		t.Fatalf("config did not correctly set default; expected 1028304, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("pmtu_disc")
	if value != "1" || err != nil {
		t.Fatalf("config did not correctly set default; expected 1, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("schedule_icmp")
	if value != "0" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	// test setting defaults via strings to simulate passing in via CLI
	cliParams := []string{"backup_only=500", "conntrack=500", "expire_quiescent_template=500", "pmtu_disc=500", "sync_ports=500", "sync_sock_size=500"}
	config, err = NewIPVSConfig(cliParams)
	if err != nil {
		t.Fatal("saw error instantiating IPVSConfig", err)
	}

	value, err = config.GetSysCtlSetting("backup_only")
	if value != "500" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("conntrack")
	if value != "500" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("expire_quiescent_template")
	if value != "500" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("pmtu_disc")
	if value != "500" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("sync_ports")
	if value != "500" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	value, err = config.GetSysCtlSetting("sync_sock_size")
	if value != "500" || err != nil {
		t.Fatalf("config did not correctly set default; expected 0, saw %s", value)
	}

	// verify an error is produced for a bogus tag and that we don't panic
	cliParams = []string{"bogus-tag"}
	_, err = NewIPVSConfig(cliParams)
	if err == nil {
		t.Fatal("should have seen an error for a bogus tag, saw <nil>")
	}

	// eg 3/19/21 - this is okay to remove because we now allow any tag from the user (trust the admin)
	// verify an error is produced for a bogus tag that is correctly formatted
	// cliParams = []string{"bogus-tag=1"}
	// _, err = NewIPVSConfig(cliParams)
	// if err == nil {
	// 	t.Fatal("should have seen an error for a bogus tag, saw <nil>")
	// }
}

// TestWriteToDisk for this to succeed, the directory structure + files need to exist already. Mac users need to do this before expecting this test to work
// you also need to run this test with sudo
func TestWriteToDisk(t *testing.T) {
	t.Skip("if let to run, this will change sysctl settings")
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
