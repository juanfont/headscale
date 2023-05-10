package headscale

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const prometheusNamespace = "headscale"

var (
	// This is a high cardinality metric (user x machines), we might want to make this
	// configurable/opt-in in the future.
	lastStateUpdate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "last_update_seconds",
		Help:      "Time stamp in unix time when a machine or headscale was updated",
	}, []string{"user", "machine"})

	machineRegistrations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "machine_registrations_total",
		Help:      "The total amount of registered machine attempts",
	}, []string{"action", "auth", "status", "user"})

	updateRequestsFromNode = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "update_request_from_node_total",
		Help:      "The number of updates requested by a node/update function",
	}, []string{"user", "machine", "state"})
	updateRequestsSentToNode = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "update_request_sent_to_node_total",
		Help:      "The number of calls/messages issued on a specific nodes update channel",
	}, []string{"user", "machine", "status"})
	// TODO(kradalby): This is very debugging, we might want to remove it.
	updateRequestsReceivedOnChannel = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "update_request_received_on_channel_total",
		Help:      "The number of update requests received on an update channel",
	}, []string{"user", "machine"})
)
