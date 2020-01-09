package vault

import (
	"gopkg.in/guregu/null.v3"
)

type Transit struct {
	Client     *Client
	MountPoint string
}

func (c *Client) Transit() *Transit {
	return c.TransitWithMountPoint("transit")
}

func (c *Client) TransitWithMountPoint(mountpoint string) *Transit {
	return &Transit{
		Client:     c,
		MountPoint: mountpoint,
	}
}

type TransitCreateOptions struct {
	ConvergentEncryption null.Bool `json:"convergent_encryption,omitempty"`
	Derived              null.Bool `json:"derived,omitempty"`
	Exportable           null.Bool `json:"exportable,omitempty"`
	AllowPlaintextBackup null.Bool `json:"allow_plaintext_backup,omitempty"`
}

func (t *Transit) Create(key string, data TransitCreateOptions) error {
	err := t.Client.Write([]string{"v1", t.MountPoint, "keys", key}, data, nil)
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
	err := t.Client.Read([]string{"v1", t.MountPoint, "keys", key}, nil, readRes)
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
	err := t.Client.Delete([]string{"v1", t.MountPoint, "keys", key}, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) ForceDelete(key string) error {
	err := t.Update(key, &TransitUpdateOptions{
		DeletionAllowed: null.BoolFrom(true),
	})
	if err != nil {
		return err
	}

	err = t.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

type TransitUpdateOptions struct {
	MinDecryptionVersion int       `json:"min_decrytion_version"`
	MinEncryptionVersion int       `json:"min_encryption_version"`
	DeletionAllowed      null.Bool `json:"deletion_allowed"`
	Exportable           null.Bool `json:"exportable"`
	AllowPlaintextBackup null.Bool `json:"allow_plaintext_backup"`
}

func (t *Transit) Update(key string, options *TransitUpdateOptions) error {
	err := t.Client.Write([]string{"v1", t.MountPoint, "keys", key, "config"}, options, nil)
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) Rotate(key string) error {
	err := t.Client.Write([]string{"v1", t.MountPoint, "keys", key, "rotate"}, nil, nil)
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

func (t *Transit) Export(key string, options *TransitExportOptions) (*TransitExportResponse, error) {
	res := &TransitExportResponse{}
	path := []string{"v1", t.MountPoint, "export", options.KeyType, key}
	if options.Version != "" {
		path = append(path, options.Version)
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

func (t *Transit) Encrypt(key string, options *TransitEncryptOptions) (*TransitEncryptResponse, error) {
	res := &TransitEncryptResponse{}
	err := t.Client.Write([]string{"v1", t.MountPoint, "encrypt", key}, options, res)
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

func (t *Transit) EncryptBatch(key string, options *TransitEncryptOptionsBatch) (*TransitEncryptResponseBatch, error) {
	res := &TransitEncryptResponseBatch{}
	err := t.Client.Write([]string{"v1", t.MountPoint, "encrypt", key}, options, res)
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

type TransitDecrpytResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

func (t *Transit) Decrpyt(key string, options *TransitDecryptOptions) (*TransitDecrpytResponse, error) {
	res := &TransitDecrpytResponse{}
	err := t.Client.Write([]string{"v1", t.MountPoint, "decrypt", key}, options, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type TransitDecryptOptionsBatch struct {
	BatchInput []TransitBatchCiphertext `json:"batch_input"`
}

type TransitDecrpytResponseBatch struct {
	Data struct {
		BatchResults []TransitBatchPlaintext `json:"batch_results"`
	} `json:"data"`
}

func (t *Transit) DecrpytBatch(key string, options *TransitDecryptOptionsBatch) (*TransitDecrpytResponseBatch, error) {
	res := &TransitDecrpytResponseBatch{}
	err := t.Client.Write([]string{"v1", t.MountPoint, "decrypt", key}, options, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
