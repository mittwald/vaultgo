package vault

import (
	"os"

	"github.com/pkg/errors"
)

const (
	//nolint:gosec // this is not a hardcoded credential
	defaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func NewKubernetesAuth(c *Client, role string, opts ...KubernetesAuthOpt) (AuthProvider, error) {
	k := &kubernetesAuth{
		Client:     c,
		mountPoint: "kubernetes",
		role:       role,
		jwtPath:    defaultServiceAccountTokenPath,
	}

	for _, opt := range opts {
		err := opt(k)
		if err != nil {
			return nil, err
		}
	}

	return k, nil
}

type kubernetesAuth struct {
	Client     *Client
	mountPoint string
	role       string
	jwt        string
	jwtPath    string
}

func loadJwt(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(err, "could not load jwt from file")
	}

	return string(content), nil
}

type AuthResponse struct {
	Auth struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		LeaseDuration int      `json:"lease_duration"`
		Renewable     bool     `json:"renewable"`
		Metadata      struct {
			Role                     string `json:"role"`
			ServiceAccountName       string `json:"service_account_name"`
			ServiceAccountNamespace  string `json:"service_account_namespace"`
			ServiceAccountSecretName string `json:"service_account_secret_name"`
			ServiceAccountUID        string `json:"service_account_uid"`
		} `json:"metadata"`
	} `json:"auth"`
}

type kubernetesAuthConfig struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

func (k kubernetesAuth) Auth() (*AuthResponse, error) {
	var err error

	jwt := k.jwt
	if jwt == "" {
		jwt, err = loadJwt(k.jwtPath)
		if err != nil {
			return nil, err
		}
	}

	conf := &kubernetesAuthConfig{
		Role: k.role,
		JWT:  jwt,
	}

	res := &AuthResponse{}

	err = k.Client.Write([]string{"v1", "auth", k.mountPoint, "login"}, conf, res, &RequestOptions{
		SkipRenewal: true,
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}
