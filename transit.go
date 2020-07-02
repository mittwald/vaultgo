package vault

import (
	"encoding/base64"
	"github.com/hashicorp/vault/api"
	"gopkg.in/guregu/null.v3"
	"net/http"
	"net/url"
)

type Transit struct {
	Client     *Client
	MountPoint string
}

func (c *Client) Transit() *Transit {
	return c.TransitWithMountPoint("transit")
}

func (c *Client) TransitWithMountPoint(mountPoint string) *Transit {
	return &Transit{
		Client:     c,
		MountPoint: mountPoint,
	}
}

type TransitCreateOptions struct {
	ConvergentEncryption null.Bool `json:"convergent_encryption,omitempty"`
	Derived              null.Bool `json:"derived,omitempty"`
	Exportable           null.Bool `json:"exportable,omitempty"`
	AllowPlaintextBackup null.Bool `json:"allow_plaintext_backup,omitempty"`
}

func (t *Transit) Create(key string, opts TransitCreateOptions) error {
	err := t.Client.Write([]string{"v1", t.MountPoint, "keys", url.PathEscape(key)}, opts, nil)
	if err != nil {
		return err
	}
	return nil
}

type TransitReadResponse struct {
	Data struct {
		Type                 string        `json:"type"`
		DeletionAllowed      bool          `json:"deletion_allowed"`
		Derived              bool          `json:"derived"`
		Exportable           bool          `json:"exportable"`
		AllowPlaintextBackup bool          `json:"allow_plaintext_backup"`
		Keys                 map[int]int64 `json:"keys"`
		MinDecryptionVersion int           `json:"min_decrytion_version"`
		MinEncryptionVersion int           `json:"min_encryption_version"`
		Name                 string        `json:"name"`
		SupportsEncryption   bool          `json:"supports_encryption"`
		SupportsDecryption   bool          `json:"supports_decryption"`
		SupportsDerivation   bool          `json:"supports_derivation"`
		SupportsSigning      bool          `json:"supports_signing"`
		LatestVersion        int           `json:"latest_version"`
	} `json:"data"`
}

func (t *Transit) Read(key string) (*TransitReadResponse, error) {
	readRes := &TransitReadResponse{}
	err := t.Client.Read([]string{"v1", t.MountPoint, "keys", url.PathEscape(key)}, nil, readRes)
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
	err := t.Client.List([]string{"v1", t.MountPoint, "keys"}, nil, readRes)
	if err != nil {
		return nil, err
	}
	return readRes, nil
}

func (t *Transit) Delete(key string) error {
	err := t.Client.Delete([]string{"v1", t.MountPoint, "keys", url.PathEscape(key)}, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) ForceDelete(key string) error {
	err := t.Update(key, TransitUpdateOptions{
		DeletionAllowed: null.BoolFrom(true),
	})
	if err != nil {
		return err
	}

	return t.Delete(key)
}

type TransitUpdateOptions struct {
	MinDecryptionVersion int       `json:"min_decrytion_version"`
	MinEncryptionVersion int       `json:"min_encryption_version"`
	DeletionAllowed      null.Bool `json:"deletion_allowed"`
	Exportable           null.Bool `json:"exportable"`
	AllowPlaintextBackup null.Bool `json:"allow_plaintext_backup"`
}

func (t *Transit) Update(key string, opts TransitUpdateOptions) error {
	err := t.Client.Write([]string{"v1", t.MountPoint, "keys", url.PathEscape(key), "config"}, opts, nil)
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) Rotate(key string) error {
	err := t.Client.Write([]string{"v1", t.MountPoint, "keys", url.PathEscape(key), "rotate"}, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

type TransitExportOptions struct {
	KeyType string `json:"key_type"`
	Version string `json:"version"`
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
	err := t.Client.Read(path, nil, res)
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
	Ciphertext string      `json:"ciphertext"`
	Context    null.String `json:"context"`
}

type TransitBatchPlaintext struct {
	Plaintext string      `json:"plaintext"`
	Context   null.String `json:"context"`
}

type TransitEncryptOptions struct {
	Plaintext            string      `json:"plaintext"`
	Context              null.String `json:"context"`
	KeyVersion           null.Int    `json:"key_version"`
	Nonce                null.String `json:"nonce"`
	Type                 null.String `json:"type"`
	ConvergentEncryption null.String `json:"convergent_encryption"`
}

type TransitEncryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

func (t *Transit) Encrypt(key string, opts TransitEncryptOptions) (*TransitEncryptResponse, error) {
	res := &TransitEncryptResponse{}
	opts.Plaintext = base64.StdEncoding.EncodeToString([]byte(opts.Plaintext))
	err := t.Client.Write([]string{"v1", t.MountPoint, "encrypt", url.PathEscape(key)}, opts, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type TransitEncryptOptionsBatch struct {
	BatchInput           []TransitBatchPlaintext `json:"batch_input"`
	KeyVersion           null.Int                `json:"key_version"`
	Type                 null.String             `json:"type"`
	ConvergentEncryption null.String             `json:"convergent_encryption"`
}

type TransitEncryptResponseBatch struct {
	Data struct {
		BatchResults []TransitBatchCiphertext `json:"batch_results"`
	} `json:"data"`
}

func (t *Transit) EncryptBatch(key string, opts TransitEncryptOptionsBatch) (*TransitEncryptResponseBatch, error) {
	res := &TransitEncryptResponseBatch{}
	for i := range opts.BatchInput {
		opts.BatchInput[i].Plaintext = base64.StdEncoding.EncodeToString([]byte(opts.BatchInput[i].Plaintext))
	}
	err := t.Client.Write([]string{"v1", t.MountPoint, "encrypt", url.PathEscape(key)}, opts, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type TransitDecryptOptions struct {
	Ciphertext string      `json:"ciphertext"`
	Context    null.String `json:"context"`
	Nonce      null.String `json:"nonce"`
}

type TransitDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

func (t *Transit) Decrypt(key string, opts TransitDecryptOptions) (*TransitDecryptResponse, error) {
	res := &TransitDecryptResponse{}
	err := t.Client.Write([]string{"v1", t.MountPoint, "decrypt", url.PathEscape(key)}, opts, res)
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
	err := t.Client.Write([]string{"v1", t.MountPoint, "decrypt", key}, opts, res)
	if err != nil {
		return nil, err
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

func (t *Transit) mapError(err error) error {
	if resErr, ok := err.(*api.ResponseError); ok {
		if resErr.StatusCode == http.StatusBadRequest {
			if len(resErr.Errors) == 1 && resErr.Errors[0] == "encryption key not found" {
				return ErrEncKeyNotFound
			}
		}
	}

	return err
}
