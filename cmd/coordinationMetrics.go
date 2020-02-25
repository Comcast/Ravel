package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/comcast/ravel/pkg/stats"
)

type coordinationMetrics struct {
	lb string

	// 1 or 0 depending on whether the worker is started or stopped
	running *prometheus.GaugeVec

	// increment whenever a check occurs, connects, or fails to connect
	connectCounter *prometheus.CounterVec

	// hazard is incremented when a master's state changes
	hazard *prometheus.CounterVec
}

func (c *coordinationMetrics) Running(connected bool) {
	val := 0.0
	if connected {
		val = 1.0
	}
	c.running.With(prometheus.Labels{
		"lb": c.lb,
	}).Set(val)
}

func (c *coordinationMetrics) Check(connected bool) {
	c.connectCounter.With(prometheus.Labels{"lb": c.lb, "result": "total"}).Add(1)
	if connected {
		c.connectCounter.With(prometheus.Labels{"lb": c.lb, "result": "success"}).Add(1)
	} else {
		c.connectCounter.With(prometheus.Labels{"lb": c.lb, "result": "fail"}).Add(1)
	}
}

func (c *coordinationMetrics) Hazard() {
	c.hazard.With(prometheus.Labels{"lb": c.lb}).Add(1)
}

func NewCoordinationMetrics(lb string) *coordinationMetrics {
	// gauge config_info
	running := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: stats.Prefix + "worker_running",
		Help: "denotes whether the worker is in a running state or a stopped state",
	}, []string{"lb"})

	connectCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "worker_connect",
		Help: "denotes whether any connection attempt has taken place. result field indicates total|success|fail.",
	}, []string{"lb", "result"})

	hazard := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "worker_hazard",
		Help: "incremented when a connection attempt has occurred and the master status has changed from prior observations",
	}, []string{"lb"})

	prometheus.MustRegister(running)
	prometheus.MustRegister(connectCounter)
	prometheus.MustRegister(hazard)

	// init error counter to  0
	hazard.With(prometheus.Labels{"lb": lb})

	return &coordinationMetrics{
		lb:             lb,
		running:        running,
		connectCounter: connectCounter,
		hazard:         hazard,
	}

}
