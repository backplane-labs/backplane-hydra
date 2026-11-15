package hydra_test

import (
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	hydra "github.com/backplane-labs/backplane-hydra"
)

// The configuration loads as the binary loads it (schemapb reflection
// included): a tag schemapb does not know stops the service at start.
func TestConfigLoads(t *testing.T) {
	t.Parallel()

	backplanetest.Config[hydra.Config](t, map[string]string{"PUBLIC_URL": "https://auth.example.com"})
}
