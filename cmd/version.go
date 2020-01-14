package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.comcast.com/viper-sde/kube2ipvs/pkg/stats"
)

var (
	version   string
	goVersion = runtime.Version()
	commit    string
	buildDate string
	arch      = runtime.GOOS + "/" + runtime.GOARCH
)

// Version prints version information and exits
func Version() *cobra.Command {

	var cmd = &cobra.Command{
		Use:           "version",
		Short:         "print version information and exit",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long:          ``,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Printf("Version:\t%s\n", version)
			fmt.Printf("Go Version:\t%s\n", goVersion)
			fmt.Printf("Commit:\t\t%s\n", commit)
			fmt.Printf("Build Date:\t%s\n", buildDate)
			fmt.Printf("OS/Arch:\t%s\n", arch)
			return nil
		},
	}

	return cmd
}

func emitVersionMetric(lb, ns, name, key string) {
	// gauge config_info
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: stats.Prefix + "info",
		Help: "version information for rdei lb",
	}, []string{"lb", "seczone", "configNamespace", "configName", "version", "goVersion", "commit", "buildDate", "arch", "startTime"})
	prometheus.MustRegister(info)

	info.With(prometheus.Labels{
		"lb":              lb,
		"seczone":         key,
		"configNamespace": ns,
		"configName":      name,
		"version":         version,
		"commit":          commit,
		"goVersion":       goVersion,
		"buildDate":       buildDate,
		"arch":            arch,
		"startTime":       time.Now().Format(time.RFC3339),
	}).Set(0)
}
