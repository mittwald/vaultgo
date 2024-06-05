package vault

import (
	"net/url"
)

const (
	pathPrefix string = "v1"
)

type KVv1 struct {
	Service
}

func (c *Client) KVv1() *KVv1 {
	return c.KVv1WithMountPoint("kv")
}

func (c *Client) KVv1WithMountPoint(mountPoint string) *KVv1 {
	return &KVv1{
		Service: Service{
			client:     c,
			MountPoint: mountPoint,
		},
	}
}

func (k *KVv1) Create(id string, data map[string]string) error {
	err := k.client.Write(
		[]string{
			pathPrefix,
			k.MountPoint,
			url.PathEscape(id),
		}, data, nil, nil,
	)
	if err != nil {
		return err
	}

	return nil
}

type KVv1ReadResponse struct {
	Data map[string]string `json:"data"`
}

func (k *KVv1) Read(key string) (*KVv1ReadResponse, error) {
	readRes := &KVv1ReadResponse{}

	err := k.client.Read(
		[]string{
			pathPrefix,
			k.MountPoint,
			url.PathEscape(key),
		}, readRes, nil,
	)
	if err != nil {
		return nil, err
	}

	return readRes, nil
}

func (k *KVv1) Delete(key string) error {
	err := k.client.Delete(
		[]string{
			pathPrefix,
			k.MountPoint,
			url.PathEscape(key),
		}, nil, nil, nil,
	)
	if err != nil {
		return err
	}

	return nil
}
