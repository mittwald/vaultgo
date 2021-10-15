package testdata

import (
	"context"
)

var Vault *VaultContainer

func Init(ctx context.Context, version string) error {
	var err error
	Vault, err = InitVaultContainer(ctx, version)

	return err
}
