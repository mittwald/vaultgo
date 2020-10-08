# Golang Library for HashiCorp vault

This is yet another golang vault client.
It uses the [official vault go client](https://github.com/hashicorp/vault/tree/master/api) 
but adds some requests and responses types and some convenient methods for an improved Developing experience.

Typing every request and response is rather time consuming, only a few vault APIs are implemented at the moment. If there is demand for us
to use other APIs, they will be added. We are also always open to Pull Requests :)

## Supported APIs

Currently, these APIs are implemented:

-   `Transit(mountPoint)`

## Authentication

Token-based and Kubernetes Auth are supported as of now.

### Token-Based

Initialize a new Vault Client using your token and endpoint:

[Example](https://pkg.go.dev/github.com/mittwald/vaultgo#example-TokenBased)

### Kubernetes In-Cluster Example

[Example](https://pkg.go.dev/github.com/mittwald/vaultgo#example-K8sInCluster)

## Usage

Once the Vault Client is created, instanciate new clients for each engine:

[TransitList Example](https://pkg.go.dev/github.com/mittwald/vaultgo#Transit.List)

### Run Tests

Tests require a running docker daemon. The test will automatically create a vault container.
```
> make test
```
