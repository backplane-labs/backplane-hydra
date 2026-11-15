package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/tracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/backplane-labs/backplane-hydra/pkg/auth"
)

// TestTracedClientCarriesTheTrace: Hydra continues the caller's trace.
func TestTracedClientCarriesTheTrace(t *testing.T) {
	t.Parallel()

	var got string

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Traceparent")
	}))
	t.Cleanup(srv.Close)

	client := auth.TracedClient(propagation.TraceContext{})

	switch client.Transport.(type) {
	case *tracehttp.Transport:
	default:
		t.Fatalf("transport %T, want a tracehttp one", client.Transport)
	}

	ctx, span := sdktrace.NewTracerProvider().Tracer("test").Start(t.Context(), "caller")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	if got == "" {
		t.Fatal("no traceparent reached Hydra")
	}
}
