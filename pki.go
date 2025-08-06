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
	KeyName          string `json:"key_name,omitempty"`
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
	NotAfter     string `json:"not_after,omitempty"`
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
	path := []string{"v1", k.MountPoint}

	if issuerRef == "" {
		path = append(path, "root", "sign-intermediate")
	} else {
		path = append(path, "issuer", issuerRef, "sign-intermediate")
	}

	err := k.client.Write(path, pkiopts, response, nil)
	if err != nil {
		return nil, err
	}

	return response, nil
}

type PKIImportCABundleRequest struct {
	PemBundle string `json:"pem_bundle"`
}
type PKIImportCABundleResponse struct {
	Data struct {
		ImportedIssuers []string          `json:"imported_issuers"`
		ImportedKeys    []string          `json:"imported_keys"`
		Mapping         map[string]string `json:"mapping"`
		ExistingIssuers []string          `json:"existing_issuers"`
		ExistingKeys    []string          `json:"existing_keys"`
	} `json:"data"`
}

func (k *PKI) ImportCaOrPrivateKey(pkiopts PKIImportCABundleRequest) (*PKIImportCABundleResponse, error) {
	response := &PKIImportCABundleResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"issuers",
			"import",
			"bundle",
		}, pkiopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}

type PKIListIssuersResponse struct {
	Data struct {
		KeyInfo map[string]struct {
			IssuerName string `json:"issuer_name"`
		} `json:"key_info"`
		Keys []string `json:"keys"`
	} `json:"data"`
}

func (k *PKI) ListIssuers() (*PKIListIssuersResponse, error) {
	response := &PKIListIssuersResponse{}
	err := k.client.List(
		[]string{
			"v1",
			k.MountPoint,
			"issuers",
		}, nil, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}

type PKIUpdateIssuerRequest struct {
	IssuerName           string   `json:"issuer_name"`
	LeafNotAfterBehavior string   `json:"leaf_not_after_behavior,omitempty"`
	ManualChain          []string `json:"manual_chain,omitempty"`
	Usage                []string `json:"usage,omitempty"`
}

type PKIUpdateIssuerResponse struct {
	Data struct {
		CACertificateChain           []string    `json:"ca_chain"`
		Certificate                  string      `json:"certificate"`
		IssuerID                     string      `json:"issuer_id"`
		IssuerName                   string      `json:"issuer_name"`
		KeyID                        string      `json:"key_id"`
		LeafNotAfterBehavior         string      `json:"leaf_not_after_behavior"`
		ManualChain                  interface{} `json:"manual_chain"`
		Usage                        string      `json:"usage"`
		RevocationSignatureAlgorithm string      `json:"revocation_signature_algorithm"`
		IssuingCertificates          []string    `json:"issuing_certificates"`
		CRLDistributionPoints        []string    `json:"crl_distribution_points"`
		DeltaCRLDistributionPoints   []string    `json:"delta_crl_distribution_points"`
		OCSPServers                  []string    `json:"ocsp_servers"`
	} `json:"data"`
}

func (k *PKI) UpdateIssuer(issuerName string, pkiopts PKIUpdateIssuerRequest) (*PKIUpdateIssuerResponse, error) {
	response := &PKIUpdateIssuerResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"issuer",
			issuerName,
		}, pkiopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}

type PKIReadIssuerResponse struct {
	Data struct {
		CACertificateChain []string `json:"ca_chain"`
		Certificate        string   `json:"certificate"`
		RevocationTime     int      `json:"revocation_time"`
	} `json:"data"`
}

func (k *PKI) ReadIssuer(issuerName string) (*PKIReadIssuerResponse, error) {
	response := &PKIReadIssuerResponse{}
	err := k.client.Read(
		[]string{
			"v1",
			k.MountPoint,
			"issuer",
			issuerName,
			"json",
		}, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}

type PKIRevokeIssuerResponse struct {
	CAChain              []string    `json:"ca_chain"`
	Certificate          string      `json:"certificate"`
	IssuerID             string      `json:"issuer_id"`
	IssuerName           string      "json:\"issuer_name\""
	KeyID                string      `json:"key_id"`
	LeafNotAfterBehavior string      `json:"leaf_not_after_behavior"`
	ManualChain          interface{} `json:"manual_chain"`
	Usage                string      `json:"usage"`
	RevocationTime       int64       `json:"revocation_time"`
}

func (k *PKI) RevokeIssuer(issuerName string) (*PKIRevokeIssuerResponse, error) {
	response := &PKIRevokeIssuerResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"issuer",
			issuerName,
			"revoke",
		}, nil, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}
