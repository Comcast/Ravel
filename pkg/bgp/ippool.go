package bgp

import "encoding/json"

type Marshals interface {
	Load(cidr string)
	Marshal() ([]byte, error)
}

type IPPoolV2 struct {
	APIVersion string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   struct {
		CIDR string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Spec struct {
		IPIP struct {
			Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
		} `json:"ipip,omitempty" yaml:"ipip,omitempty"`
		NatOutgoing bool `json:"nat-outgoing,omitempty" yaml:"nat-outgoing,omitempty"`
		Disabled    bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	} `json:"spec,omitempty" yaml:"spec,omitempty"`
}

func (i *IPPoolV2) Load(cidr string) {
	i.APIVersion = "v1"
	i.Kind = "ipPool"
	i.Metadata.CIDR = cidr
	i.Spec.Disabled = true
	i.Spec.NatOutgoing = true
}

func (i *IPPoolV2) Marshal() ([]byte, error) {
	return json.Marshal(i)
}

type IPPoolV3 struct {
	APIVersion string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Spec struct {
		CIDR        string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
		IPIPMode    string `json:"ipipMode,omitempty" yaml:"ipipMode,omitempty"`
		NatOutgoing bool   `json:"natOutgoing,omitempty" yaml:"natOutgoing,omitempty"`
		Disabled    bool   `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	} `json:"spec,omitempty" yaml:"spec,omitempty"`
}

func (i *IPPoolV3) Load(cidr string) {
	i.APIVersion = "v1"
	i.Kind = "ipPool"
	i.Metadata.Name = "ravel-" + cidr
	i.Spec.CIDR = cidr
	i.Spec.Disabled = true
	i.Spec.NatOutgoing = true
}

func (i *IPPoolV3) Marshal() ([]byte, error) {
	return json.Marshal(i)
}
