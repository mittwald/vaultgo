package vault

import (
	"fmt"
	"log"
)

func Example_tokenBased() {
	c, err := NewClient("https://vault:8200/",
		WithCaPath(""),
		WithAuthToken("SECRET"),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(c.Address())
}

func Example_k8sInCluster() {
	c, err := NewClient("https://vault:8200/", WithCaPath(""), WithKubernetesAuth("myrole"))
	if err != nil {
		log.Fatal(err)
	}

	log.Println(c.Address())
}

func ExampleTransit_List() {
	c, err := NewClient("https://vault:8200/",
		WithCaPath(""),
		WithAuthToken("SECRET"),
	)
	if err != nil {
		log.Fatal(err)
	}

	l, err := c.TransitWithMountPoint("transit").List()
	if err != nil {
		log.Fatal()
	}

	log.Println(l)
}

func Example_encryptDecryptType() {
	const rsa4096 = "rsa-4096"
	c, err := NewClient("https://vault:8200/", WithCaPath(""), WithAuthToken("test"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.Token())

	transit := c.Transit()

	key := "test123bacd"

	err = transit.Create(key, &TransitCreateOptions{
		Exportable: BoolPtr(true),
		Type:       rsa4096,
	})
	if err != nil {
		log.Fatal(err)
	}

	res, err := transit.Read(key)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("%+v\n", res.Data)
	}

	exportRes, err := transit.Export(key, TransitExportOptions{
		KeyType: "encryption-key",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%v+", exportRes.Data.Keys[1])

	encryptResponse, err := transit.Encrypt(key, &TransitEncryptOptions{
		Plaintext: "plaintext",
	})
	if err != nil {
		log.Fatalf("Error occurred during encryption: %v", err)
	}
	log.Println("Ciphertext: ", encryptResponse.Data.Ciphertext)

	decryptResponse, err := transit.Decrypt(key, &TransitDecryptOptions{
		Ciphertext: encryptResponse.Data.Ciphertext,
	})
	if err != nil {
		log.Fatalf("Error occurred during decryption: %v", err)
	}
	log.Println("Plaintext: ", decryptResponse.Data.Plaintext)
}
