package main

import (
	"fmt"
	"os"
	"strings"
)

func readRules(path string) ([]string, error) {

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	out := []string{}

	for _, l := range lines {
		if strings.Contains(l, "-A INPUT ") {
			out = append(out, l)
		}
	}

	return out, nil
}

// sudo iptables -I INPUT -s 10.131.157.162  -d 10.131.153.123 -dport 4001 -j ACCEPT -m comment --comment "RAVEL-INGRESS"
// sudo iptables -I INPUT -d 10.131.153.123 -dport 4001 -j DROP -m comment --comment "RAVEL-INGRESS"
// all the DROP RULES At the END
func main() {

	currentRules, err := readRules("current-rules")
	if err != nil {
		fmt.Println(err)
		return
	}

	newRules, err := readRules("new-rules")
	if err != nil {
		fmt.Println(err)
		return
	}

	add, delete := diffRules(currentRules, newRules)

	fmt.Printf("\n# DELETE %d RULES \n", len(delete))
	if len(delete) > 0 {
		fmt.Println("sudo iptables\n  " + strings.Join(delete, "\n  "))
	}

	fmt.Printf("\n# ADD %d RULES\n", len(add))

	newCmdA := []string{}
	newCmdI := []string{}

	for _, a := range add {
		if strings.Contains(a, " DROP") {
			newCmdA = append(newCmdA, "-A "+a[3:])
		} else {
			newCmdI = append(newCmdI, "-I "+a[3:])
		}
	}
	if len(newCmdI) > 0 {
		fmt.Println("sudo iptables\n  " + strings.Join(newCmdI, "\n  "))
	}
	if len(newCmdA) > 0 {
		fmt.Println("sudo iptables\n  " + strings.Join(newCmdA, "\n  "))
	}
	fmt.Println("")
}

func diffRules(currentRules, newRules []string) ([]string, []string) {

	add := []string{}
	delete := []string{}

	// delete missing rules
	for _, c := range currentRules {
		found := false
		for _, n := range newRules {
			if c == n {
				found = true
				break
			}
		}
		if !found {
			delete = append(delete, "-D "+c[3:])
		}
	}

	// add new rules
	for _, c := range newRules {
		found := false
		for _, n := range currentRules {
			if c == n {
				found = true
				break
			}
		}
		if !found {
			add = append(add, c)
		}
	}

	return add, delete
}
