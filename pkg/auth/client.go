package auth

import (
	"net/http"

	"github.com/backplane-labs/backplane/pkg/backplane/tracehttp"
	"go.opentelemetry.io/otel/propagation"
)

// tracedClient is the default client of Hydra's endpoints: every call is a
// client span carrying the trace context with propagator, which Hydra, part
// of the installation, continues.
func tracedClient(propagator propagation.TextMapPropagator) *http.Client {
	return &http.Client{
		Timeout:   defaultTimeout,
		Transport: tracehttp.NewTransport(nil, tracehttp.WithPropagator(propagator)),
	}
}
