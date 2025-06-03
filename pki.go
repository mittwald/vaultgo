package vault

type PKI struct {
	Service
}

func (c *Client) PKI() *PKI {
	return c.PKIWithMountPoint("pki")
}

func (c *Client) PKIWithMountPoint(mountPoint string) *PKI {
	return &PKI{
		Service: Service{
			client:     c,
			MountPoint: mountPoint,
		},
	}
}

type PKIIssueOptions struct {
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl,omitempty"`
}

type PKIIssueResponse struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		SerialNumber   string   `json:"serial_number"`
		Expiration     int      `json:"expiration"`
		PrivateKeyType string   `json:"private_key_type"`
		PrivateKey     string   `json:"private_key"`
		IssuingCA      string   `json:"issuing_ca"`
		CAChain        []string `json:"ca_chain"`
		Certificate    string   `json:"certificate"`
	} `json:"data"`
}

func (k *PKI) Issue(role string, pkiopts PKIIssueOptions) (*PKIIssueResponse, error) {
	response := &PKIIssueResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"issue",
			role,
		}, pkiopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}
