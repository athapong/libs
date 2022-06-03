package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

// NewVaultAppRoleClient logs in to Vault using the AppRole authentication
// method, returning an authenticated client and the auth token itself, which
// can be periodically renewed.
func newVaultAppRoleClient(ctx context.Context, parameters vaultParameters) (*Vault, *api.Secret, error) {
	log.Printf("connecting to vault @ %s", parameters.Address)

	config := api.DefaultConfig() // modify for more granular configuration
	config.Address = parameters.Address

	client, err := api.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize vault client: %w", err)
	}

	vault := &Vault{
		client:     client,
		parameters: parameters,
	}

	token, err := vault.login(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("vault login error: %w", err)
	}
	log.Println("connecting to vault: success!")

	return vault, token, nil
}

// A combination of a RoleID and a SecretID is required to log into Vault
// with AppRole authentication method. The SecretID is a value that needs
// to be protected, so instead of the app having knowledge of the SecretID
// directly, we have a trusted orchestrator (simulated with a script here)
// give the app access to a short-lived response-wrapping token.
//
// ref: https://www.vaultproject.io/docs/concepts/response-wrapping
// ref: https://learn.hashicorp.com/tutorials/vault/secure-introduction?in=vault/app-integration#trusted-orchestrator
// ref: https://learn.hashicorp.com/tutorials/vault/approle-best-practices?in=vault/auth-methods#secretid-delivery-best-practices
func (v *Vault) login(ctx context.Context) (*api.Secret, error) {
	log.Printf("logging in to vault with approle auth; role id: %s", v.parameters.ApproleRoleID)

	approleSecretID := &approle.SecretID{
		FromFile: v.parameters.ApproleSecretIDFile,
	}

	appRoleAuth, err := approle.NewAppRoleAuth(
		v.parameters.ApproleRoleID,
		approleSecretID,
		approle.WithWrappingToken(), // only required if the SecretID is response-wrapped
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize approle authentication method: %w", err)
	}

	authInfo, err := v.client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login using approle auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no approle info was returned after login")
	}
	log.Println("logging in to vault with approle auth: success!")

	return authInfo, nil
}

// GetSecretAPIKey fetches the latest version of secret api key from kv-v2
func (v *Vault) getSecretAPIKeys() (map[string]string, error) {
	log.Println("getting secret api key from vault")

	secret, err := v.client.Logical().Read(v.parameters.ApiKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret: %w", err)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("malformed secret returned")
	}

	apiKeys := strings.Split(v.parameters.ApiKeyField, ",")
	if len(apiKeys) == 0 {
		return nil, fmt.Errorf("the secret key does not provide")
	}

	apiValues := make(map[string]string)
	for _, val := range apiKeys {
		apiKey, ok := data[val]
		if !ok {
			return nil, fmt.Errorf("the secret retrieved from vault is missing %q field", val)
		}

		apiKeyString, ok := apiKey.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected secret key type for %q field", apiKey)
		}
		apiValues[val] = apiKeyString
	}
	log.Println("getting secret api key from vault: success!")

	return apiValues, nil
}

// GetDatabaseCredentials retrieves a new set of temporary database credentials
func (v *Vault) GetDatabaseCredentials() (Credentials, *api.Secret, error) {
	log.Println("getting temporary database credentials from vault")

	lease, err := v.client.Logical().Read(v.parameters.DatabaseCredentialsPath)
	if err != nil {
		return Credentials{}, nil, fmt.Errorf("unable to read secret: %w", err)
	}

	b, err := json.Marshal(lease.Data)
	if err != nil {
		return Credentials{}, nil, fmt.Errorf("malformed credentials returned: %w", err)
	}

	var credentials Credentials
	if err := json.Unmarshal(b, &credentials); err != nil {
		return Credentials{}, nil, fmt.Errorf("unable to unmarshal credentials: %w", err)
	}

	log.Println("getting temporary database credentials from vault: success!")

	// raw secret is included to renew database credentials
	return credentials, lease, nil
}
