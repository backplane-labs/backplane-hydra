package activities_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/backplane-labs/backplane-hydra/internal/activities"
)

func TestWithClientID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, want string
		err              bool
	}{
		{"sets the id", `{"client_name":"app"}`, `{"client_id":"app-1","client_name":"app"}`, false},
		{"keeps the same id", `{"client_id":"app-1"}`, `{"client_id":"app-1"}`, false},
		{"empty body", ``, `{"client_id":"app-1"}`, false},
		{"another id", `{"client_id":"other"}`, ``, true},
		{"id not a string", `{"client_id":1}`, ``, true},
		{"not an object", `[1]`, ``, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := activities.WithClientID(json.RawMessage(tc.body), "app-1")
			if tc.err {
				if !errors.Is(err, activities.ErrClientBody) {
					t.Fatalf("err = %v, want ErrClientBody", err)
				}

				return
			}

			if err != nil || string(got) != tc.want {
				t.Fatalf("withClientID = %s, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func BenchmarkWithClientID(b *testing.B) {
	body := json.RawMessage(`{"client_name":"app","grant_types":["authorization_code"],"redirect_uris":["https://a/cb"]}`)
	for b.Loop() {
		if _, err := activities.WithClientID(body, "app-1"); err != nil {
			b.Fatal(err)
		}
	}
}
