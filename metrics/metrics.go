package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	PromNamespace = "local_sts"
	PromSubsystem = "http"
)

var (
	ActionCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: PromNamespace,
		Subsystem: PromSubsystem,
		Name:      "requests_to_action_count",
	}, []string{"action"})
	ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: PromNamespace,
		Subsystem: PromSubsystem,
		Name:      "requests_error_count",
	}, []string{"error"})
)
