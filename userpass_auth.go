package vault

func NewUserpassAuth(c *Client, username string, password string, opts ...UserpassAuthOpt) (AuthProvider, error) {
	k := &UserpassAuth{
		Client:     c,
		mountPoint: "userpass",
		username:   username,
		password:   password,
	}

	for _, opt := range opts {
		err := opt(k)
		if err != nil {
			return nil, err
		}
	}

	return k, nil
}

type UserpassAuth struct {
	Client     *Client
	mountPoint string
	username   string
	password   string
}

type userpassAuthConfig struct {
	Password string `json:"password"`
}

func (k UserpassAuth) Auth() (*AuthResponse, error) {
	conf := &userpassAuthConfig{
		Password: k.password,
	}

	res := &AuthResponse{}

	err := k.Client.Write([]string{"v1", "auth", k.mountPoint, "login", k.username}, conf, res, &RequestOptions{
		SkipRenewal: true,
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

type UserpassAuthOpt func(k *UserpassAuth) error

func WithUserpassMountPoint(mountPoint string) UserpassAuthOpt {
	return func(k *UserpassAuth) error {
		k.mountPoint = mountPoint

		return nil
	}
}
