package iptables

import (
	"strings"

	"github.comcast.com/viper-sde/kube2ipvs/pkg/util"
)

type RuleSet struct {
	ChainRule string   //    :KUBE-SVC-ZEHG7HT725H2KQF7 - [0:0]
	Rules     []string // -A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
}

// GetSaveLines parses the iptables-save as a string and puts it into a map[string]*kubeRules
// Modifications were made from the Kube codebase to support iptables save/restore
func GetSaveLines(table util.Table, save []byte) (map[string]*RuleSet, error) {
	chainsMap := map[string]*RuleSet{}

	tablePrefix := "*" + string(table)
	readIndex := 0
	// find beginning of table
	for readIndex < len(save) {
		line, n := ReadLine(readIndex, save)
		readIndex = n
		if strings.HasPrefix(line, tablePrefix) {
			break
		}
	}

	// parse table lines
	for readIndex < len(save) {

		line, n := ReadLine(readIndex, save)
		readIndex = n
		// Ignore empty lines with whitespace stripped
		if len(strings.Join(strings.Fields(line), "")) == 0 {
			continue
		}

		// Extract the chain identity from the line. Chains are identified by either
		// a ':' prefix, indicating they are a chain, or by a '-' prefix, indicating a
		// rule in a chain.
		var chain string
		if strings.HasPrefix(line, "COMMIT") || strings.HasPrefix(line, "*") {
			break
		} else if strings.HasPrefix(line, "#") {
			continue
		} else if strings.HasPrefix(line, ":") {
			chain = strings.SplitN(line[1:], " ", 2)[0]
			// Get the ruleset if it exists in the map, otherwise create it
			if _, ok := chainsMap[chain]; !ok {
				chainsMap[chain] = &RuleSet{
					ChainRule: line,
				}
			}

		} else if strings.HasPrefix(line, "-") {
			chain = strings.SplitN(line[3:], " ", 2)[0]
		}

		// Capture the line
		if strings.HasPrefix(line, "-") {
			chainsMap[chain].Rules = append(chainsMap[chain].Rules, line)
		}
	}
	return chainsMap, nil
}

func ReadLine(readIndex int, byteArray []byte) (string, int) {
	currentReadIndex := readIndex

	// consume left spaces
	for currentReadIndex < len(byteArray) {
		if byteArray[currentReadIndex] == ' ' {
			currentReadIndex++
		} else {
			break
		}
	}

	// leftTrimIndex stores the left index of the line after the line is left-trimmed
	leftTrimIndex := currentReadIndex

	// rightTrimIndex stores the right index of the line after the line is right-trimmed
	// it is set to -1 since the correct value has not yet been determined.
	rightTrimIndex := -1

	for ; currentReadIndex < len(byteArray); currentReadIndex++ {
		if byteArray[currentReadIndex] == ' ' {
			// set rightTrimIndex
			if rightTrimIndex == -1 {
				rightTrimIndex = currentReadIndex
			}
		} else if (byteArray[currentReadIndex] == '\n') || (currentReadIndex == (len(byteArray) - 1)) {
			// end of line or byte buffer is reached
			if currentReadIndex <= leftTrimIndex {
				return "", currentReadIndex + 1
			}
			// set the rightTrimIndex
			if rightTrimIndex == -1 {
				rightTrimIndex = currentReadIndex
				if currentReadIndex == (len(byteArray)-1) && (byteArray[currentReadIndex] != '\n') {
					// ensure that the last character is part of the returned string,
					// unless the last character is '\n'
					rightTrimIndex = currentReadIndex + 1
				}
			}
			return string(byteArray[leftTrimIndex:rightTrimIndex]), currentReadIndex + 1
		} else {
			// unset rightTrimIndex
			rightTrimIndex = -1
		}
	}
	return "", currentReadIndex
}
