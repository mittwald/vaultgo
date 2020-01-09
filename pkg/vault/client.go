package vault

import (
	"encoding/json"
	vault "github.com/hashicorp/vault/api"
	"io/ioutil"
	"net/url"
)

type Client struct {
	vault.Client
	Config Config
}

type Config struct {
	vault.Config
}

func NewClient(c *vault.Config) (*Client, error) {
	client, err := vault.NewClient(c)
	if err != nil {
		return nil, err
	}

	return &Client{Client: *client}, nil
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

