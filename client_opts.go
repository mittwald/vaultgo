package vault

type ClientOpts func(c *Client) error

func WithAuthProvider(p AuthProvider, autoRenew bool, renewErrs chan<- error) ClientOpts {
	return func(c *Client) error {
		a := NewTokenAuth(c, p)

		err := a.Auth()
		if err != nil {
			return err
		}

		if autoRenew {
			a.EnableAutoRenew(renewErrs)
		}

		return nil
	}
}

func WithKubernetesAuth(role string, autoRenew bool, renewErrs chan<- error, opts ...KubernetesAuthOpt) ClientOpts {
	return func(c *Client) error {
		k8AuthProvider, err := NewKubernetesAuth(c, role, opts...)
		if err != nil {
			return err
		}

		withProviderFunc := WithAuthProvider(k8AuthProvider, autoRenew, renewErrs)

		return withProviderFunc(c)
	}
}

func WithAuthToken(token string) ClientOpts {
	return func(c *Client) error {
		c.SetToken(token)
		return nil
	}
}
