package notifier

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const prometheusNamespace = "headscale"

var (
	notifierWaitForLock = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "notifier_wait_for_lock_seconds",
		Help:      "histogram of time spent waiting for the notifier lock",
		Buckets:   []float64{0.001, 0.01, 0.1, 0.3, 0.5, 1, 3, 5, 10},
	}, []string{"action"})
	notifierUpdateSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "notifier_update_sent_total",
		Help:      "total count of update sent on nodes channel",
	}, []string{"status", "type", "trigger"})
	notifierUpdateReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "notifier_update_received_total",
		Help:      "total count of updates received by notifier",
	}, []string{"type", "trigger"})
	notifierNodeUpdateChans = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "notifier_open_channels_total",
		Help:      "total count open channels in notifier",
	})
)
