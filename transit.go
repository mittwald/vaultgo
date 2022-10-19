package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/hashicorp/vault/api"
)

type Transit struct {
	Service
}

func (c *Client) Transit() *Transit {
	return c.TransitWithMountPoint("transit")
}

func (c *Client) TransitWithMountPoint(mountPoint string) *Transit {
	return &Transit{
		Service: Service{
			client:     c,
			MountPoint: mountPoint,
		},
	}
}

type TransitCreateOptions struct {
	ConvergentEncryption *bool  `json:"convergent_encryption,omitempty"`
	Derived              *bool  `json:"derived,omitempty"`
	Exportable           *bool  `json:"exportable,omitempty"`
	AllowPlaintextBackup *bool  `json:"allow_plaintext_backup,omitempty"`
	Type                 string `json:"type,omitempty"`
}

func (t *Transit) Create(key string, opts *TransitCreateOptions) error {
	err := t.client.Write([]string{"v1", t.MountPoint, "keys", url.PathEscape(key)}, opts, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

type TransitReadResponse struct {
	Data TransitReadResponseData `json:"data"`
}

type TransitReadResponseData struct {
	Name                 string              `json:"name"`
	Type                 string              `json:"type"`
	Keys                 map[int]interface{} `json:"keys"`
	MinDecryptionVersion int                 `json:"min_decrytion_version"`
	MinEncryptionVersion int                 `json:"min_encryption_version"`
	LatestVersion        int                 `json:"latest_version"`
	DeletionAllowed      bool                `json:"deletion_allowed"`
	Derived              bool                `json:"derived"`
	Exportable           bool                `json:"exportable"`
	AllowPlaintextBackup bool                `json:"allow_plaintext_backup"`
	SupportsEncryption   bool                `json:"supports_encryption"`
	SupportsDecryption   bool                `json:"supports_decryption"`
	SupportsDerivation   bool                `json:"supports_derivation"`
	SupportsSigning      bool                `json:"supports_signing"`
}

func (t *Transit) Read(key string) (*TransitReadResponse, error) {
	readRes := &TransitReadResponse{}

	err := t.client.Read([]string{"v1", t.MountPoint, "keys", url.PathEscape(key)}, readRes, nil)
	if err != nil {
		return nil, err
	}

	return readRes, nil
}

type TransitListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

func (t *Transit) List() (*TransitListResponse, error) {
	readRes := &TransitListResponse{}

	err := t.client.List([]string{"v1", t.MountPoint, "keys"}, nil, readRes, nil)
	if err != nil {
		return nil, err
	}

	return readRes, nil
}

func (t *Transit) Delete(key string) error {
	err := t.client.Delete([]string{"v1", t.MountPoint, "keys", url.PathEscape(key)}, nil, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (t *Transit) ForceDelete(key string) error {
	err := t.Update(key, TransitUpdateOptions{
		DeletionAllowed: BoolPtr(true),
	})
	if err != nil {
		return err
	}

	return t.Delete(key)
}

type TransitUpdateOptions struct {
	MinDecryptionVersion int   `json:"min_decrytion_version,omitempty"`
	MinEncryptionVersion int   `json:"min_encryption_version,omitempty"`
	DeletionAllowed      *bool `json:"deletion_allowed,omitempty"`
	Exportable           *bool `json:"exportable,omitempty"`
	AllowPlaintextBackup *bool `json:"allow_plaintext_backup,omitempty"`
}

func (t *Transit) Update(key string, opts TransitUpdateOptions) error {
	err := t.client.Write([]string{"v1", t.MountPoint, "keys", url.PathEscape(key), "config"}, opts, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (t *Transit) Rotate(key string) error {
	err := t.client.Write([]string{"v1", t.MountPoint, "keys", url.PathEscape(key), "rotate"}, nil, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

type TransitExportOptions struct {
	KeyType string `json:"key_type"`
	Version string `json:"version,omitempty"`
}

type TransitExportResponse struct {
	Data struct {
		Name string         `json:"name"`
		Keys map[int]string `json:"keys"`
		Type string         `json:"type"`
	} `json:"data"`
}

func (t *Transit) Export(key string, opts TransitExportOptions) (*TransitExportResponse, error) {
	res := &TransitExportResponse{}
	path := []string{"v1", t.MountPoint, "export", opts.KeyType, url.PathEscape(key)}

	if opts.Version != "" {
		path = append(path, opts.Version)
	}

	err := t.client.Read(path, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (t *Transit) KeyExists(key string) (bool, error) {
	keys, err := t.List()
	if err != nil {
		return false, err
	}

	for _, k := range keys.Data.Keys {
		if k == key {
			return true, nil
		}
	}

	return false, nil
}

type TransitBatchCiphertext struct {
	Ciphertext string `json:"ciphertext"`
	Context    string `json:"context,omitempty"`
}

type TransitBatchPlaintext struct {
	Plaintext string `json:"plaintext"`
	Context   string `json:"context,omitempty"`
}

type TransitEncryptOptions struct {
	Plaintext            string `json:"plaintext"`
	Context              string `json:"context,omitempty"`
	KeyVersion           *int   `json:"key_version,omitempty"`
	Nonce                string `json:"nonce,omitempty"`
	Type                 string `json:"type,omitempty"`
	ConvergentEncryption string `json:"convergent_encryption,omitempty"`
}

type TransitEncryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

func (t *Transit) Encrypt(key string, opts *TransitEncryptOptions) (*TransitEncryptResponse, error) {
	res := &TransitEncryptResponse{}

	opts.Plaintext = base64.StdEncoding.EncodeToString([]byte(opts.Plaintext))

	err := t.client.Write([]string{"v1", t.MountPoint, "encrypt", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

type TransitEncryptOptionsBatch struct {
	BatchInput           []TransitBatchPlaintext `json:"batch_input"`
	KeyVersion           *int                    `json:"key_version,omitempty"`
	Type                 string                  `json:"type,omitempty"`
	ConvergentEncryption string                  `json:"convergent_encryption,omitempty"`
}

type TransitEncryptResponseBatch struct {
	Data struct {
		BatchResults []TransitBatchCiphertext `json:"batch_results"`
	} `json:"data"`
}

func (t *Transit) EncryptBatch(key string, opts *TransitEncryptOptionsBatch) (*TransitEncryptResponseBatch, error) {
	res := &TransitEncryptResponseBatch{}

	for i := range opts.BatchInput {
		opts.BatchInput[i].Plaintext = base64.StdEncoding.EncodeToString([]byte(opts.BatchInput[i].Plaintext))
	}

	err := t.client.Write([]string{"v1", t.MountPoint, "encrypt", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

type TransitDecryptOptions struct {
	Ciphertext string `json:"ciphertext"`
	Context    string `json:"context,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
}

type TransitDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

func (t *Transit) Decrypt(key string, opts *TransitDecryptOptions) (*TransitDecryptResponse, error) {
	res := &TransitDecryptResponse{}

	err := t.client.Write([]string{"v1", t.MountPoint, "decrypt", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, t.mapError(err)
	}

	blob, err := base64.StdEncoding.DecodeString(res.Data.Plaintext)
	if err != nil {
		return nil, err
	}

	res.Data.Plaintext = string(blob)

	return res, nil
}

type TransitDecryptOptionsBatch struct {
	BatchInput []TransitBatchCiphertext `json:"batch_input"`
}

type TransitDecryptResponseBatch struct {
	Data struct {
		BatchResults []TransitBatchPlaintext `json:"batch_results"`
	} `json:"data"`
}

func (t *Transit) DecryptBatch(key string, opts TransitDecryptOptionsBatch) (*TransitDecryptResponseBatch, error) {
	res := &TransitDecryptResponseBatch{}

	err := t.client.Write([]string{"v1", t.MountPoint, "decrypt", key}, opts, res, nil)
	if err != nil {
		return nil, t.mapError(err)
	}

	for i := range res.Data.BatchResults {
		blob, err := base64.StdEncoding.DecodeString(res.Data.BatchResults[i].Plaintext)
		if err != nil {
			return nil, err
		}

		res.Data.BatchResults[i].Plaintext = string(blob)
	}

	return res, nil
}

type TransitSignOptions struct {
	Input               string `json:"input"`
	KeyVersion          *int   `json:"key_version,omitempty"`
	HashAlgorithm       string `json:"hash_algorithm,omitempty"`
	Context             string `json:"context,omitempty"`
	Prehashed           bool   `json:"prehashed,omitempty"`
	SignatureAlgorithm  string `json:"signature_algorithm,omitempty"`
	MarshalingAlgorithm string `json:"marshaling_algorithm,omitempty"`
	SaltLength          string `json:"salt_length,omitempty"`
}

type TransitSignResponse struct {
	Data struct {
		Signature  string `json:"signature"`
		KeyVersion int    `json:"key_version,omitempty"`
	} `json:"data"`
}

func (t *Transit) Sign(key string, opts *TransitSignOptions) (*TransitSignResponse, error) {
	res := &TransitSignResponse{}

	opts.Input = base64.StdEncoding.EncodeToString([]byte(opts.Input))

	err := t.client.Write([]string{"v1", t.MountPoint, "sign", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

type TransitBatchSignInput struct {
	Input   string `json:"input"`
	Context string `json:"context,omitempty"`
}

type TransitBatchSignature struct {
	Signature  string `json:"signature"`
	KeyVersion int    `json:"key_version,omitempty"`
}

type TransitSignOptionsBatch struct {
	BatchInput          []TransitBatchSignInput `json:"batch_input"`
	KeyVersion          *int                    `json:"key_version,omitempty"`
	HashAlgorithm       string                  `json:"hash_algorithm,omitempty"`
	Prehashed           bool                    `json:"prehashed,omitempty"`
	SignatureAlgorithm  string                  `json:"signature_algorithm,omitempty"`
	MarshalingAlgorithm string                  `json:"marshaling_algorithm,omitempty"`
	SaltLength          string                  `json:"salt_length,omitempty"`
}

type TransitSignResponseBatch struct {
	Data struct {
		BatchResults []TransitBatchSignature `json:"batch_results"`
	} `json:"data"`
}

func (t *Transit) SignBatch(key string, opts *TransitSignOptionsBatch) (*TransitSignResponseBatch, error) {
	res := &TransitSignResponseBatch{}

	for i := range opts.BatchInput {
		opts.BatchInput[i].Input = base64.StdEncoding.EncodeToString([]byte(opts.BatchInput[i].Input))
	}

	err := t.client.Write([]string{"v1", t.MountPoint, "sign", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

type TransitVerifyOptions struct {
	Input               string `json:"input"`
	Signature           string `json:"signature"`
	HashAlgorithm       string `json:"hash_algorithm,omitempty"`
	Context             string `json:"context,omitempty"`
	Prehashed           bool   `json:"prehashed,omitempty"`
	SignatureAlgorithm  string `json:"signature_algorithm,omitempty"`
	MarshalingAlgorithm string `json:"marshaling_algorithm,omitempty"`
	SaltLength          string `json:"salt_length,omitempty"`
}

type TransitVerifyResponse struct {
	Data struct {
		Valid bool `json:"valid"`
	} `json:"data"`
}

func (t *Transit) Verify(key string, opts *TransitVerifyOptions) (*TransitVerifyResponse, error) {
	res := &TransitVerifyResponse{}

	opts.Input = base64.StdEncoding.EncodeToString([]byte(opts.Input))

	err := t.client.Write([]string{"v1", t.MountPoint, "verify", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

type TransitBatchVerifyInput struct {
	Input     string `json:"input"`
	Signature string `json:"signature"`
	Context   string `json:"context,omitempty"`
}

type TransitBatchVerifyData struct {
	Valid bool `json:"valid"`
}

type TransitVerifyOptionsBatch struct {
	BatchInput          []TransitBatchVerifyInput `json:"batch_input"`
	HashAlgorithm       string                    `json:"hash_algorithm,omitempty"`
	Context             string                    `json:"context,omitempty"`
	Prehashed           bool                      `json:"prehashed,omitempty"`
	SignatureAlgorithm  string                    `json:"signature_algorithm,omitempty"`
	MarshalingAlgorithm string                    `json:"marshaling_algorithm,omitempty"`
	SaltLength          string                    `json:"salt_length,omitempty"`
}

type TransitVerifyResponseBatch struct {
	Data struct {
		BatchResults []TransitBatchVerifyData `json:"batch_results"`
	} `json:"data"`
}

func (t *Transit) VerifyBatch(key string, opts *TransitVerifyOptionsBatch) (*TransitVerifyResponseBatch, error) {
	res := &TransitVerifyResponseBatch{}

	for i := range opts.BatchInput {
		opts.BatchInput[i].Input = base64.StdEncoding.EncodeToString([]byte(opts.BatchInput[i].Input))
	}

	err := t.client.Write([]string{"v1", t.MountPoint, "verify", url.PathEscape(key)}, opts, res, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// DecodeCipherText gets payload from vault ciphertext format (removes "vault:v<ver>:" prefix)
func DecodeCipherText(vaultCipherText string) (string, int, error) {
	regex := regexp.MustCompile(`^vault:v(\d+):(.+)$`)
	matches := regex.FindStringSubmatch(vaultCipherText)
	if len(matches) != 3 {
		return "", 0, errors.New("invalid vault ciphertext format")
	}

	keyVersion, err := strconv.Atoi(matches[1])
	if err != nil {
		return "", 0, errors.New("can't parse key version")
	}

	return matches[2], keyVersion, nil
}

// EncodeCipherText encodes payload to vault ciphertext format (adda "vault:v<ver>:" prefix)
func EncodeCipherText(cipherText string, keyVersion int) string {
	return fmt.Sprintf("vault:v%d:%s", keyVersion, cipherText)
}

func (t *Transit) mapError(err error) error {
	resErr := &api.ResponseError{}
	if errors.As(err, &resErr) {
		if resErr.StatusCode == http.StatusBadRequest {
			if len(resErr.Errors) == 1 && resErr.Errors[0] == "encryption key not found" {
				return ErrEncKeyNotFound
			}
		}
	}

	return err
}
