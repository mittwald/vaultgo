package vault

type SSH struct {
	Service
}

func (c *Client) SSH() *SSH {
	return c.SSHWithMountPoint("ssh")
}

func (c *Client) SSHWithMountPoint(mountPoint string) *SSH {
	return &SSH{
		Service: Service{
			client:     c,
			MountPoint: mountPoint,
		},
	}
}

type SSHSignOptions struct {
	PublicKey       string `json:"public_key"`
	CertType        string `json:"cert_type,omitempty"`
	ValidPrincipals string `json:"valid_principals,omitempty"`
}

type SSHSignResponse struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		SerialNumber string `json:"serial_number"`
		SignedKey    string `json:"signed_key"`
	} `json:"data"`
}

type SSHReadPubKeyResponse struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		PublicKey string `json:"public_key"`
	} `json:"data"`
}

func (k *SSH) Sign(role string, sshopts SSHSignOptions) (*SSHSignResponse, error) {
	response := &SSHSignResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"sign",
			role,
		}, sshopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (k *SSH) GetVaultPubKey() (string, error) {
	response := &SSHReadPubKeyResponse{}
	err := k.client.Read(
		[]string{
			"v1",
			k.MountPoint,
			"config",
			"ca",
		}, response, nil,
	)
	if err != nil {
		return "", err
	}

	return response.Data.PublicKey, nil
}
