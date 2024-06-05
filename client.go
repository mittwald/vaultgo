package vault

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"

	"github.com/hashicorp/vault/api"
)

type Client struct {
	*api.Client

	auth    AuthProvider
	conf    *api.Config
	tlsConf *TLSConfig
}

type Service struct {
	client     *Client
	MountPoint string
}

type RequestOptions struct {
	Parameters url.Values

	// SkipRenewal defines if the client should retry this Request with a new Token if it fails because of
	// 403 Permission Denied
	// The default behavior of the client is to always Request a new Token on 403
	// Only if this is explicitly set to true, the client will continue processing the first failed request
	// and skip the renewal
	// This should generally only be disabled for TokenAuth requests (a failed TokenAuth request can't be fixed by
	// doing another TokenAuth request, this would lead to infinite recursion)
	SkipRenewal bool
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

	client := &Client{
		Client:  vaultClient,
		conf:    conf,
		tlsConf: tlsConf,
	}

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

func (c *Client) reloadTLSConfig() error {
	return c.conf.ConfigureTLS(c.tlsConf.TLSConfig)
}

func (c *Client) Request(method string, path []string, body, response interface{}, opts *RequestOptions) error {
	if opts == nil {
		opts = &RequestOptions{}
	}

	pathString := resolvePath(path)
	r := c.NewRequest(method, pathString)

	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			return errors.Wrap(err, "failed to marshal body as JSON")
		}
	}

	if opts.Parameters != nil {
		r.Params = opts.Parameters
	}

	//nolint:staticcheck
	resp, err := c.RawRequest(r)
	isTokenExpiredErr := resp != nil && resp.StatusCode == http.StatusForbidden && c.auth != nil
	isCertExpiredErr := err != nil && errors.As(err, &x509.UnknownAuthorityError{})
	if (isTokenExpiredErr || isCertExpiredErr) && !opts.SkipRenewal {
		if resp != nil {
			_ = resp.Body.Close()
		}

		if c.tlsConf != nil {
			reloadErr := c.reloadTLSConfig()
			if reloadErr != nil {
				return errors.Wrapf(reloadErr, "tlsconfig reload failed after request failed with %q", err.Error())
			}
		}

		if c.auth != nil {
			tokenErr := c.renewToken()
			if tokenErr != nil {
				return errors.Wrap(tokenErr, "token renew after request returned 403 failed")
			}
		}

		// We have to build a new request, the new token has to be set in that one
		// Renewal has to be skipped to make sure we never renew in a loop.
		opts.SkipRenewal = true
		return c.Request(method, path, body, response, opts)
	} else if err != nil {
		return errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()

	if response == nil {
		return nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "error reading response body")
	}

	if err = json.Unmarshal(respBody, response); err != nil {
		return errors.Wrap(err, "error unmarshalling body into response struct")
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

func (c *Client) Put(path []string, body, response interface{}, opts *RequestOptions) error {
	return c.Request("PUT", path, body, response, opts)
}
