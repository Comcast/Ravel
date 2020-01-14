package system

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

func generateCertFile(filename string) (apiServer string, certFilename string, err error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	// unmarshal
	kc := &kubeConfig{}
	err = yaml.Unmarshal(b, kc)
	if err != nil {
		return
	}

	// validate
	if len(kc.Clusters) != 1 || len(kc.Users) != 1 {
		err = fmt.Errorf("invalid cluster or user count. clusters=%d users=%d", len(kc.Clusters), len(kc.Users))
		return
	}

	// decode data
	var cert, key []byte

	cert, err = base64.StdEncoding.DecodeString(kc.Users[0].User.ClientKeyData)
	if err != nil {
		return
	}
	key, err = base64.StdEncoding.DecodeString(kc.Users[0].User.ClientCertificateData)
	if err != nil {
		return
	}

	// write the tempfile.
	tmpfile, err := ioutil.TempFile("", "kube-config")
	if err != nil {
		return
	}
	out := string(cert) + "\n" + string(key)
	if _, err = tmpfile.Write([]byte(out)); err != nil {
		return
	}
	if err = tmpfile.Close(); err != nil {
		return
	}

	apiServer = kc.Clusters[0].Cluster.Server
	certFilename = tmpfile.Name()
	return
}

type kubeConfig struct {
	APIVersion     string   `yaml:"apiVersion"`
	CurrentContext string   `yaml:"current-context"`
	Kind           string   `yaml:"kind"`
	Preferences    struct{} `yaml:"preferences"`

	Clusters []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`

	Contexts []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`

	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}
