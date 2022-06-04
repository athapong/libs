package vault

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// GetSecretsByKubernetesAuth returns secrets from Vault using Kubernetes auth method
func GetSecretsByKubernetesAuth(ctx context.Context, env Environment) (map[string]string, error) {
	ctx, cancelContextFunc := context.WithCancel(ctx)
	defer cancelContextFunc()

	vault, secret, err := newVaultKubernetesAuthClient(
		ctx,
		vaultParameters{
			Address:                   env.VaultAddress,
			ApproleRoleID:             env.VaultApproleRoleID,
			ApproleJwtTokenFile:       env.KubernetesEnv.VaultApproleJwtTokenFile,
			DatabaseCredentialsPath:   env.KubernetesEnv.VaultDatabaseCredsPath,
			DatabaseCredentialsFields: env.KubernetesEnv.VaultDatabaseCredsFields,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize vault kubernetes auth client: %w", err)
	}

	values := make(map[string]string)
	if env.KubernetesEnv.VaultDatabaseCredsFields == "" {
		return nil, fmt.Errorf("the secret key does not provide")
	}

	credFields := strings.Split(env.KubernetesEnv.VaultDatabaseCredsFields, ",")
	for _, cred := range credFields {
		value, err := vault.getSecretWithKubernetesAuth(secret, cred)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve secret from vault: %w", err)
		}
		values[cred] = value
	}

	return values, nil
}

// GetCredentialsByAppRole retrieve database credential from secret engine 'database'
func GetCredentialsByAppRole(ctx context.Context, env Environment) (Credentials, error) {
	ctx, cancelContextFunc := context.WithCancel(ctx)
	defer cancelContextFunc()

	vault, _, err := newVaultAppRoleClient(
		ctx,
		vaultParameters{
			Address:             env.VaultAddress,
			ApproleRoleID:       env.VaultApproleRoleID,
			ApproleSecretIDFile: env.SecretIDEnv.VaultApproleSecretIDFile,
			APIKeyPath:          env.SecretIDEnv.VaultAPIKeyPath,
			APIKeyField:         env.SecretIDEnv.VaultAPIKeyField,
		},
	)
	if err != nil {
		return Credentials{}, fmt.Errorf("unable to initialize vault connection @ %s: %w", env.VaultAddress, err)
	}

	// database credentials/lease
	databaseCredentials, databaseCredentialsLease, err := vault.GetDatabaseCredentials()
	if err != nil {
		return Credentials{}, fmt.Errorf("unable to retrieve database credentials from vault: %w", err)
	}

	log.Printf("Credentials lease duration: %v", databaseCredentialsLease.LeaseDuration)

	return databaseCredentials, nil
}

// GetSecretsByAppRole retrieve secret from secret engine by AppRole
func GetSecretsByAppRole(ctx context.Context, env Environment, creds ...string) (map[string]string, error) {
	ctx, cancelContextFunc := context.WithCancel(ctx)
	defer cancelContextFunc()

	vault, _, err := newVaultAppRoleClient(
		ctx,
		vaultParameters{
			Address:             env.VaultAddress,
			ApproleRoleID:       env.VaultApproleRoleID,
			ApproleSecretIDFile: env.SecretIDEnv.VaultApproleSecretIDFile,
			APIKeyPath:          env.SecretIDEnv.VaultAPIKeyPath,
			APIKeyField:         env.SecretIDEnv.VaultAPIKeyField,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize vault connection @ %s: %w", env.VaultAddress, err)
	}

	secrets, err := vault.getSecretAPIKeys()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve secret from vault: %w", err)
	}

	return secrets, nil
}
