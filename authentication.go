package vault

type Authentication struct {
	Service
}

func (c *Client) Authentication() *Authentication {
	return c.AuthenticationWithMountPoint("auth")
}

func (c *Client) AuthenticationWithMountPoint(mountPoint string) *Authentication {
	return &Authentication{
		Service: Service{
			client:     c,
			MountPoint: mountPoint,
		},
	}
}

type AuthCreateTokenRequest struct {
	RoleName        string                 `json:"role_name,omitempty"`
	ID              string                 `json:"id,omitempty"`
	Policies        []string               `json:"policies,omitempty"`
	Meta            map[string]interface{} `json:"meta,omitempty"`
	NoParent        bool                   `json:"no_parent,omitempty"`
	NoDefaultPolicy bool                   `json:"no_default_policy,omitempty"`
	Renewable       bool                   `json:"renewable,omitempty"`
	TTL             string                 `json:"ttl,omitempty"`
	Type            string                 `json:"type,omitempty"`
	EntityAlias     string                 `json:"entity_alias,omitempty"`
}

type AuthCreateTokenResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      []string    `json:"warnings"`
	Auth          struct {
		ClientToken   string      `json:"client_token"`
		Accessor      string      `json:"accessor"`
		Policies      []string    `json:"policies"`
		TokenPolicies []string    `json:"token_policies"`
		Metadata      interface{} `json:"metadata"`
		LeaseDuration int         `json:"lease_duration"`
		Renewable     bool        `json:"renewable"`
		EntityID      string      `json:"entity_id"`
		TokenType     string      `json:"token_type"`
		Orphan        bool        `json:"orphan"`
		NumUses       int         `json:"num_uses"`
	} `json:"auth"`
	MountType string `json:"mount_type"`
}

func (k *Authentication) CreateOrphanToken(pkiopts AuthCreateTokenRequest) (*AuthCreateTokenResponse, error) {
	response := &AuthCreateTokenResponse{}
	err := k.client.Write(
		[]string{
			"v1",
			k.MountPoint,
			"token",
			"create-orphan",
		}, pkiopts, response, nil,
	)
	if err != nil {
		return nil, err
	}

	return response, nil
}
