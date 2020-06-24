package main

import (
	"fmt"
	vault "gitlab.mittwald.it/coab-0x7e7/libraries/vaultgo/pkg/vault"
	"gopkg.in/guregu/null.v3"
	"log"
)

func main() {
	c, err := vault.NewClient("https://vault:8200/", vault.WithCaPath(""), vault.WithAuthToken("test"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.Token())

	transit := c.Transit()

	key := "test123bacd"

	err = transit.Create(key, vault.TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	if err != nil {
		log.Fatal(err)
	}

	res, err := transit.Read(key)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("%+v\n", res.Data)
	}

	exportRes, err := transit.Export(key, &vault.TransitExportOptions{
		KeyType: "encryption-key",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v+", exportRes.Data.Keys[1])
}
