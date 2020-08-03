package main

import (
	"fmt"
	"log"

	vault "github.com/mittwald/vaultgo"
	"gopkg.in/guregu/null.v3"
)

func main() {
	const rsa4096 = "rsa-4096"
	c, err := vault.NewClient("https://vault:8200/", vault.WithCaPath(""), vault.WithAuthToken("test"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.Token())

	transit := c.Transit()

	key := "test123bacd"

	err = transit.Create(key, &vault.TransitCreateOptions{
		Exportable: null.BoolFrom(true),
		Type:       rsa4096,
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

	exportRes, err := transit.Export(key, vault.TransitExportOptions{
		KeyType: "encryption-key",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v+", exportRes.Data.Keys[1])

	encryptResponse, err := transit.Encrypt(key, &vault.TransitEncryptOptions{
		Plaintext: "plaintext",
	})
	if err != nil {
		log.Fatalf("Error occurred during encryption: %v", err)
	}
	fmt.Println("Ciphertext: ", encryptResponse.Data.Ciphertext)

	decryptResponse, err := transit.Decrypt(key, &vault.TransitDecryptOptions{
		Ciphertext: encryptResponse.Data.Ciphertext,
	})
	if err != nil {
		log.Fatalf("Error occurred during decryption: %v", err)
	}
	fmt.Println("Plaintext: ", decryptResponse.Data.Plaintext)
}
