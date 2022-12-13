package testdata

import (
	"context"
	"fmt"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var VaultVersions = []string{"1.6.7", "1.7.5", "1.8.4", "1.9.3"}

type VaultContainer struct {
	container  testcontainers.Container
	mappedPort nat.Port
	hostIP     string
	token      string
}

func (v *VaultContainer) URI() string {
	return fmt.Sprintf("http://%s:%s/", v.HostIP(), v.Port())
}

func (v *VaultContainer) Port() string {
	return v.mappedPort.Port()
}

func (v *VaultContainer) HostIP() string {
	return v.hostIP
}

func (v *VaultContainer) Token() string {
	return v.token
}

func (v *VaultContainer) Terminate(ctx context.Context) error {
	return v.container.Terminate(ctx)
}

func InitVaultContainer(ctx context.Context, version string) (*VaultContainer, error) {
	port := nat.Port("8200/tcp")
	token := "test"

	req := testcontainers.ContainerRequest{
		Image:        "vault:" + version,
		ExposedPorts: []string{string(port)},
		WaitingFor:   wait.ForListeningPort(port),
		Env: map[string]string{
			"VAULT_ADDR":              fmt.Sprintf("http://0.0.0.0:%s", port.Port()),
			"VAULT_DEV_ROOT_TOKEN_ID": token,
			"VAULT_TOKEN":             token,
			"VAULT_LOG_LEVEL":         "trace",
		},
		Cmd: []string{
			"server",
			"-dev",
		},
		Privileged: true,
	}

	v, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	vc := &VaultContainer{
		container:  v,
		mappedPort: "",
		hostIP:     "",
		token:      token,
	}

	vc.hostIP, err = v.Host(ctx)
	if err != nil {
		return nil, err
	}

	vc.mappedPort, err = v.MappedPort(ctx, port)
	if err != nil {
		return nil, err
	}

	_, _, err = vc.container.Exec(ctx, []string{
		"vault",
		"secrets",
		"enable",
		"transit",
	})
	if err != nil {
		return nil, err
	}

	return vc, nil
}
