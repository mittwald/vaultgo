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

type PKIGenerateIntermediateOptions struct {
	CommonName       string `json:"common_name"`
	KeyName          string `json:"key_name"`
	AltNames         string `json:"alt_names,omitempty"`
	Format           string `json:"format,omitempty"`
	PrivateKeyFormat string `json:"private_key_format,omitempty"`
	KeyType          string `json:"key_type,omitempty"`
}

type PKIGenerateIntermediateResponse struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		CSR            string `json:"csr"`
		PrivateKey     string `json:"private_key"`
		PrivateKeyType string `json:"private_key_type"`
	} `json:"data"`
}

func (k *PKI) GenerateIntermediate(intermediateType string, pkiopts PKIGenerateIntermediateOptions) (*PKIGenerateIntermediateResponse, error) {
	response := &PKIGenerateIntermediateResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"intermediate",
			"generate",
			intermediateType,
		}, pkiopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}

type PKISignIntermediateOptions struct {
	CSR          string `json:"csr"`
	CommonName   string `json:"common_name"`
	AltNames     string `json:"alt_names,omitempty"`
	TTL          string `json:"ttl,omitempty"`
	Format       string `json:"format,omitempty"`
	KeyUsage     string `json:"key_usage,omitempty"`
	UseCSRValues bool   `json:"use_csr_values,omitempty"`
}

type PKISignIntermediateResponse struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Expiration   int      `json:"expiration"`
		Certificate  string   `json:"certificate"`
		IssuingCA    string   `json:"issuing_ca"`
		CAChain      []string `json:"ca_chain"`
		SerialNumber string   `json:"serial_number"`
	} `json:"data"`
}

func (k *PKI) SignIntermediate(issuerRef string, pkiopts PKISignIntermediateOptions) (*PKISignIntermediateResponse, error) {
	response := &PKISignIntermediateResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"issuer",
			issuerRef,
			"sign-intermediate",
		}, pkiopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}
