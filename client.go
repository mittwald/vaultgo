package vault

import (
	"encoding/json"
	"io/ioutil"
	"net/url"

	"github.com/hashicorp/vault/api"
)

type Client struct {
	*api.Client
}

type TLSConfig struct {
	*api.TLSConfig
}

func WithCaCert(cert string) *TLSConfig {
	return &TLSConfig{
		&api.TLSConfig{CACert: cert},
	}
}

func WithCaPath(path string) *TLSConfig {
	return &TLSConfig{
		&api.TLSConfig{CAPath: path},
	}
}

func NewClient(addr string, tlsConf *TLSConfig, opts ...ClientOpts) (*Client, error) {
	conf := api.DefaultConfig()

	conf.Address = addr

	if tlsConf != nil {
		if err := conf.ConfigureTLS(tlsConf.TLSConfig); err != nil {
			return nil, err
		}
	}

	vaultClient, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}

	client := &Client{Client: vaultClient}

	for _, opt := range opts {
		err := opt(client)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (c *Client) Request(method string, path []string, body interface{}, parameters url.Values, response interface{}) error {
	pathString := resolvePath(path)
	r := c.NewRequest(method, pathString)

	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			return err
		}
	}

	if parameters != nil {
		r.Params = parameters
	}

	resp, err := c.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if response != nil {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if err = json.Unmarshal(respBody, response); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) Read(path []string, parameters url.Values, response interface{}) error {
	return c.Request("GET", path, nil, parameters, response)
}

func (c *Client) Write(path []string, body, response interface{}) error {
	return c.Request("POST", path, body, nil, response)
}

func (c *Client) Delete(path []string, body, response interface{}) error {
	return c.Request("DELETE", path, body, nil, response)
}

func (c *Client) List(path []string, body, response interface{}) error {
	return c.Request("LIST", path, body, nil, response)
}
