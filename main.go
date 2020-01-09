package main

import (
	"fmt"
	hcvault "github.com/hashicorp/vault/api"
	vault "gitlab.mittwald.it/coab-0x7e7/libraries/vaultgo/pkg/vault"
	"gopkg.in/guregu/null.v3"
)

func main() {
	key := "test123bacd";
	conf := hcvault.DefaultConfig()
	conf.Address = "http://localhost:8200/"

	c, _ := vault.NewClient(conf)

	c.SetToken("test")

	transit := c.Transit()

	err := transit.Create(key, vault.TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	if err != nil {
		fmt.Println(err)
	}

	res, err := transit.Read(key)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", res.Data)
	}

	exportRes, err := transit.Export(key, &vault.TransitExportOptions{
		KeyType: "encryption-key",
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v+", exportRes.Data.Keys[1])
}