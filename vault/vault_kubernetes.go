package vault

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
)

func newVaultKubernetesAuthClient(ctx context.Context, parameters vaultParameters) (*Vault, *api.Secret, error) {
	config := api.DefaultConfig() // modify for more granular configuration
	config.Address = parameters.Address

	client, _ := api.NewClient(config)

	vault := &Vault{
		client:     client,
		parameters: parameters,
	}

	// Read the service-account token from the path where the token's Kubernetes Secret is mounted.
	// By default, Kubernetes will mount this to /var/run/secrets/kubernetes.io/serviceaccount/token
	jwt, err := ioutil.ReadFile(parameters.ApproleJwtTokenFile)
	if err != nil {
		return vault, nil, fmt.Errorf("unable to read file containing service account token: %w", err)
	}

	params := map[string]interface{}{
		"jwt":  string(jwt),
		"role": parameters.ApproleRoleID, // the name of the role in Vault that was created with this app's Kubernetes service account bound to it
	}

	// log in to Vault's Kubernetes auth method
	resp, err := vault.client.Logical().Write("auth/kubernetes/login", params)
	if err != nil {
		return vault, nil, fmt.Errorf("unable to log in with Kubernetes auth: %w", err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return vault, nil, fmt.Errorf("login response did not return client token")
	}

	// now you will use the resulting Vault token for making all future calls to Vault
	vault.client.SetToken(resp.Auth.ClientToken)

	// get secret from Vault
	secret, err := vault.client.Logical().Read(vault.parameters.DatabaseCredentialsPath)
	if err != nil {
		return vault, nil, fmt.Errorf("unable to read secret: %w", err)
	}

	return vault, secret, nil
}

// GetSecretWithKubernetesAuth Fetches a key-value secret (kv-v2) after authenticating to Vault with a Kubernetes service account.
// As the client, all we need to do is pass along the JWT token representing our application's Kubernetes Service Account in our login request to Vault.
func (v *Vault) getSecretWithKubernetesAuth(secret *api.Secret, key string) (string, error) {

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("data type assertion failed: %T %#v", secret.Data["data"], secret.Data["data"])
	}

	// data map can contain more than one key-value pair, in this case we're just grabbing one of them
	value, ok := data[key].(string)
	if !ok {
		return "", fmt.Errorf("value type assertion failed: %T %#v", data[key], data[key])
	}

	return value, nil
}
