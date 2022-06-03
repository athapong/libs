//go:build integration

package vault_test

import (
	"context"
	"os"
	"testing"

	"github.com/athapong/libs/vault"
	"github.com/stretchr/testify/assert"
)

func TestGetSecretsByKubernetesAuth(t *testing.T) {
	os.WriteFile("./jwttoken", []byte("eyJhbGciOiJSUzI1NiIsImtpZCI6Imo5c2VSc2VDWEg5UkVDaVBYRXFYTm1Hb3dleXE4ZnNuUUZYUVlUZUM3TWMifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjg1Nzg5Mzk0LCJpYXQiOjE2NTQyNTMzOTQsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJkZXZ3ZWJhcHAiLCJ1aWQiOiI4Yjc1YmNmZS02MTc0LTQ3ZGQtYTVkOC03ODMzZjNhYjBlMDQifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6InZhdWx0LWF1dGgiLCJ1aWQiOiI0ODZiNTk1ZC1mYzY0LTQ5ODUtOTE0MS1jMGFjMGNiOWZiYzAifSwid2FybmFmdGVyIjoxNjU0MjU3MDAxfSwibmJmIjoxNjU0MjUzMzk0LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDp2YXVsdC1hdXRoIn0.Iv890d3xZCaGe5WPwaIJm1a9jwiEU8OnbzjhpmKzr3VUKN8vpdazFHVYZzCwk-S-HP7adATdyUB2awD_xp9XV70C2SVKewNKnYD1RP2ZSFfz_6X_CeCMl88e3wp5g1RvLnmN7am61y-pwX45tJYk1qxgOXI1evOApNttLDJzweT-7s7tEdAmhRVCHyhdZ0VibyDImGzVUUZVUXulGp398zvO8aZ4UNtUFMCyafi_IY1YmUV5CNLXCMuGFrTy9YVyABbgjUx-mAehb4nN6rpPQkZmvgl5RL9FuAhzlhrEkSoK_St2f5sXO839VF4b4s-Bs7qcObzAuquzLuBSlTSBrQ"), 0644)

	env := vault.Environment{
		VaultAddress:       "http://localhost:8200",
		VaultApproleRoleID: "example",
		KubernetesEnv: vault.KubernetesEnv{
			VaultApproleJwtTokenFile: "./jwttoken",
			VaultDatabaseCredsPath:   "secret/data/myapp/config",
			VaultDatabaseCredsFields: "username,password",
		},
	}
	t.Run("success", func(t *testing.T) {
		keys, _ := vault.GetSecretsByKubernetesAuth(context.Background(), env)
		assert.Equal(t, "appuser", keys["username"])
		assert.Equal(t, "password", keys["password"])
		os.Remove("./jwttoken")
	})
}
