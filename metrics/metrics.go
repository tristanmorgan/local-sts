package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PromNamespace is a prefix to metrics
const PromNamespace = "local_sts"

// PromSubsystem adds a sub-section to metrics
const PromSubsystem = "http"

// ActionCount metrics counter for differnt actions
var ActionCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: PromNamespace,
	Subsystem: PromSubsystem,
	Name:      "requests_to_action_count",
}, []string{"action"})

// ErrorCount metrics counter for differnt errors
var ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: PromNamespace,
	Subsystem: PromSubsystem,
	Name:      "requests_error_count",
}, []string{"error"})
