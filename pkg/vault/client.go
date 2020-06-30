package vault

import (
	"encoding/json"
	vault "github.com/hashicorp/vault/api"
	"io/ioutil"
	"log"
	"net/url"
)

type Client struct {
	vault.Client
}

type TLSConfig struct {
	*vault.TLSConfig
}

func WithCaCert(cert string) *TLSConfig {
	return &TLSConfig{
		&vault.TLSConfig{CACert: cert},
	}
}

func WithCaPath(path string) *TLSConfig {
	return &TLSConfig{
		&vault.TLSConfig{CAPath: ""},
	}
}

func NewClient(addr string, tlsConf *TLSConfig, opts ...ClientOpts) (*Client, error) {
	conf := vault.DefaultConfig()
	conf.Address = addr
	if tlsConf != nil {
		err := conf.ConfigureTLS(tlsConf.TLSConfig)
		if err != nil {
			log.Fatal(err)
		}
	}

	vaultClient, err := vault.NewClient(conf)
	if err != nil {
		return nil, err
	}
	client := &Client{Client: *vaultClient}
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

func (c *Client) Write(path []string, body interface{}, response interface{}) error {
	return c.Request("POST", path, body, nil, response)
}

func (c *Client) Delete(path []string, body interface{}, response interface{}) error {
	return c.Request("DELETE", path, body, nil, response)
}

func (c *Client) List(path []string, body interface{}, response interface{}) error {
	return c.Request("LIST", path, body, nil, response)
}
