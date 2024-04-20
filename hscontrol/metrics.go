package hscontrol

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const prometheusNamespace = "headscale"

var (
	mapResponseSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_sent_total",
		Help:      "total count of mapresponses sent to clients",
	}, []string{"status", "type"})
	mapResponseUpdateReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_updates_received_total",
		Help:      "total count of mapresponse updates received on update channel",
	}, []string{"type"})
	mapResponseWriteUpdatesInStream = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_write_updates_in_stream_total",
		Help:      "total count of writes that occured in a stream session, pre-68 nodes",
	}, []string{"status"})
	mapResponseEndpointUpdates = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_endpoint_updates_total",
		Help:      "total count of endpoint updates received",
	}, []string{"status"})
	mapResponseReadOnly = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_readonly_requests_total",
		Help:      "total count of readonly requests received",
	}, []string{"status"})
	mapResponseSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_current_sessions_total",
		Help:      "total count open map response sessions",
	})
	mapResponseRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_rejected_new_sessions_total",
		Help:      "total count of new mapsessions rejected",
	}, []string{"reason"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "http_duration_seconds",
		Help:      "Duration of HTTP requests.",
	}, []string{"path"})
	httpCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "http_requests_total",
		Help:      "Total number of http requests processed",
	}, []string{"code", "method", "path"},
	)
)

// prometheusMiddleware implements mux.MiddlewareFunc.
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()

		// Ignore streaming and noise sessions
		// it has its own router further down.
		if path == "/ts2021" || path == "/machine/map" || path == "/derp" || path == "/derp/probe" || path == "/bootstrap-dns" {
			next.ServeHTTP(w, r)
			return
		}

		rw := &respWriterProm{ResponseWriter: w}

		timer := prometheus.NewTimer(httpDuration.WithLabelValues(path))
		next.ServeHTTP(rw, r)
		timer.ObserveDuration()
		httpCounter.WithLabelValues(strconv.Itoa(rw.status), r.Method, path).Inc()
	})
}

type respWriterProm struct {
	http.ResponseWriter
	status      int
	written     int64
	wroteHeader bool
}

func (r *respWriterProm) WriteHeader(code int) {
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *respWriterProm) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}
