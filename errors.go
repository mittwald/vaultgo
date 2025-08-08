package vault

import "errors"

var (
	ErrEncKeyNotFound = errors.New("encryption key not found")
	ErrIssuerNotFound = errors.New("issuer not found")
)
