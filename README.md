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

```go
package main

import (
	vault "gitlab.mittwald.it/coab-0x7e7/libraries/vaultgo/pkg/vault"
	"log"
)

func main() {
	c, err := vault.NewClient("https://vault:8200/", 
        vault.WithCaPath(""),
        vault.WithAuthToken("SECRET"),
    )
	if err != nil {
		log.Fatal(err)
    }
}
```

### Kubernetes In-Cluster Example

```go
package main

import (
	vault "gitlab.mittwald.it/coab-0x7e7/libraries/vaultgo/pkg/vault"
	"log"
)

func main() {
	renewErrs := make(chan error)
	vault.WithKubernetesAuth("test", true, renewErrs)
	c, err := vault.NewClient("https://vault:8200/", vault.WithCaPath(""), vault.WithKubernetesAuth("myrole", true, renewErrs))
	go func() {
		for {
			err := <-renewErrs
			if err != nil {
				log.Fatal(err)
			}
		}
	}()
}
```

## Usage

Once the Vault Client is created, instanciate new clients for each engine:

```
// returns Transit client (uses mountpoint transit)
transit := c.Transit()
transit := c.TransitWithMountPoint("transit")
```

### Run Tests
```
> docker-compose up -d
> make test
```
