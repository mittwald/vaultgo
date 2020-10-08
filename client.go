package vault

import (
	"encoding/json"
	"io/ioutil"
	"net/url"

	"github.com/hashicorp/vault/api"
)

type Client struct {
	*api.Client

	auth AuthProvider
}

type Service struct {
	client     *Client
	MountPoint string
}

type RequestOptions struct {
	Parameters url.Values

	// RenewToken defines if the client should retry this Request with a new Token if it fails because of
	// 403 Permission Denied
	// The default behavior of the client is to always Request a new Token on 403
	// Only if this is explicitly set to false, the client will continue processing the first failed request
	// This should generally only be disabled for TokenAuth requests (a failed TokenAuth request can't be fixed by
	// doing another TokenAuth request, this would lead to infinite recursion)
	RenewToken *bool
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

	if client.auth != nil {
		if err := client.renewToken(); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (c *Client) renewToken() error {
	res, err := c.auth.Auth()
	if err != nil {
		return err
	}

	c.SetToken(res.Auth.ClientToken)

	return nil
}

func (c *Client) Request(method string, path []string, body, response interface{}, opts *RequestOptions) error {
	pathString := resolvePath(path)
	r := c.NewRequest(method, pathString)

	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			return err
		}
	}

	if opts != nil && opts.Parameters != nil {
		r.Params = opts.Parameters
	}

	resp, err := c.RawRequest(r)
	if err != nil {
		return err
	}

	tokenRenewRequested := opts != nil && (opts.RenewToken == nil || *opts.RenewToken)
	if resp.StatusCode == 403 && c.auth != nil && tokenRenewRequested {
		_ = resp.Body.Close()

		err = c.renewToken()
		if err != nil {
			return err
		}

		resp, err = c.RawRequest(r)
		if err != nil {
			return err
		}
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(respBody, response); err != nil {
		return err
	}

	return nil
}

func (c *Client) Read(path []string, response interface{}, opts *RequestOptions) error {
	return c.Request("GET", path, nil, response, opts)
}

func (c *Client) Write(path []string, body, response interface{}, opts *RequestOptions) error {
	return c.Request("POST", path, body, response, opts)
}

func (c *Client) Delete(path []string, body, response interface{}, opts *RequestOptions) error {
	return c.Request("DELETE", path, body, response, opts)
}

func (c *Client) List(path []string, body, response interface{}, opts *RequestOptions) error {
	return c.Request("LIST", path, body, response, opts)
}
