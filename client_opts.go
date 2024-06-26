package vault

type ClientOpts func(c *Client) error

func WithKubernetesAuth(role string, opts ...KubernetesAuthOpt) ClientOpts {
	return func(c *Client) error {
		k8AuthProvider, err := NewKubernetesAuth(c, role, opts...)
		if err != nil {
			return err
		}

		c.auth = k8AuthProvider

		return nil
	}
}

func WithAuthToken(token string) ClientOpts {
	return func(c *Client) error {
		c.SetToken(token)
		return nil
	}
}

func WithUserpassAuth(username string, password string, opts ...UserpassAuthOpt) ClientOpts {
	return func(c *Client) error {
		userpassAuthProvider, err := NewUserpassAuth(c, username, password, opts...)
		if err != nil {
			return err
		}

		c.auth = userpassAuthProvider

		return nil
	}
}
