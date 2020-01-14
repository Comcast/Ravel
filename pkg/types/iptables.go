package types

// XXX these are only used by trouble...

// KubeRules contains two sets of iptables rules for insertion or management,
// one of MASQ instructions, and one of JUMP instructions. There is a 1:1
// correspondance between masq and jump rules in iptables.
//
// This structure is used in order to ensure that the rules are always paired
// together. In particular, the compareAndPrune and compareAndCreate functions
// always manage generated rules together. This ensures that the rules are
// represented in the correct order inside of iptables.
type KubeRules struct {
	Masq RulesSet
	Jump RulesSet
}

// RulesSet is a list of iptables rules.
type RulesSet []string
