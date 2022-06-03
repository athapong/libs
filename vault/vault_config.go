package vault

import "github.com/hashicorp/vault/api"

type vaultParameters struct {
	// connection parameters
	Address       string
	ApproleRoleID string

	ApproleSecretIDFile string // specified whether secret id file or
	ApproleJwtTokenFile string // jwt token file

	// the locations / field names of our two secrets
	ApiKeyPath  string
	ApiKeyField string

	DatabaseCredentialsPath   string
	DatabaseCredentialsFields string
}

type Config struct {
	Token   string
	Address string
	Path    string
	Debug   bool
}

type Vault struct {
	client     *api.Client
	parameters vaultParameters
}

// DatabaseCredentials is a set of dynamic credentials retrieved from Vault
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Vault address, approle login credentials, and secret locations
type Environment struct {
	VaultAddress       string //"VAULT_ADDRESS" 					default:"localhost:8200"               description:"Vault address"`
	VaultApproleRoleID string //"VAULT_APPROLE_ROLE_ID"         	required:"true"                        description:"Does require AppRole RoleID to log in to Vault"`
	KubernetesEnv      KubernetesEnv
	SecretIDEnv        SecretIDEnv
}

type KubernetesEnv struct {
	VaultApproleJwtTokenFile string //"VAULT_APPROLE_JWT_TOKEN_FILE"	default:"/var/run/secrets/kubernetes.io/serviceaccount/token" 	description:"AppRole JWT token file path to log in to Vault"`
	VaultDatabaseCredsPath   string //"VAULT_DATABASE_CREDS_PATH"     	default:"database/creds/dev-readonly"  							description:"Temporary database credentials will be generated here"`
	VaultDatabaseCredsFields string //"VAULT_DATABASE_CREDS_FIELDS"   	default:"username,password"  									description:"Database credentials field name will be generated here"`
}

type SecretIDEnv struct {
	VaultApproleSecretIDFile string //"VAULT_APPROLE_SECRET_ID_FILE"  default:"/tmp/secret"                  						description:"AppRole SecretID file path to log in to Vault"`
	VaultAPIKeyPath          string //"VAULT_API_KEY_PATH"            default:"kv-v2/data/api-key"           						description:"Path to the API key used by 'secure-sevice'`
	VaultAPIKeyField         string //"VAULT_API_KEY_FIELD"           default:"api-key-field"                						description:"The secret field name for the API key"`
}
