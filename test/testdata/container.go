package testdata

import (
	"context"
)

var Vault *VaultContainer

func Init(ctx context.Context) error {
	var err error
	Vault, err = InitVaultContainer(ctx)

	return err
}
