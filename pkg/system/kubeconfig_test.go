package system

import (
	"fmt"
	"testing"
)

func TestKubeConfig(t *testing.T) {
	api, filename, err := generateCertFile("../../kubeconfig")
	fmt.Println(api, filename, err)
}
