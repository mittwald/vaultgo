package vault

import (
	"testing"

	hcvault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/suite"
	"gopkg.in/guregu/null.v3"
)

type TransitTestSuite struct {
	suite.Suite
	client *Transit
}

func TestTransitTestSuite(t *testing.T) {
	conf := hcvault.DefaultConfig()
	conf.Address = "http://localhost:8200/"

	client, _ := NewClient(conf)
	client.SetToken("test")
	transit := client.Transit()

	transitTestSuite := new(TransitTestSuite)
	transitTestSuite.client = transit

	suite.Run(t, transitTestSuite)
}

func (s *TransitTestSuite) TestCreateAndRead() {
	err := s.client.Create("testCreateAndRead", TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	res, err := s.client.Read("testCreateAndRead")
	s.NoError(err)

	s.Equal(true, res.Data.Exportable)
}

func (s *TransitTestSuite) TestCreateAndList() {
	err := s.client.Create("testCreateAndList", TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	res, err := s.client.List()
	s.NoError(err)

	s.Contains(res.Data.Keys, "testCreateAndList")
	s.NotContains(res.Data.Keys, "testListDoesNotExists")
}

func (s *TransitTestSuite) TestCreateListAllowDelete() {
	key := "testCreateListAllowDelete"
	err := s.client.Create(key, TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	res, err := s.client.List()
	s.NoError(err)
	s.Contains(res.Data.Keys, key)

	err = s.client.Update(key, &TransitUpdateOptions{
		DeletionAllowed: null.BoolFrom(true),
	})
	s.NoError(err)

	err = s.client.Delete(key)
	s.NoError(err)

	res, err = s.client.List()
	s.NoError(err)
	s.NotContains(res.Data.Keys, key)
}

func (s *TransitTestSuite) TestCreateListForceDelete() {
	key := "testCreateListForceDelete"
	err := s.client.Create(key, TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	res, err := s.client.List()
	s.NoError(err)
	s.Contains(res.Data.Keys, key)

	err = s.client.ForceDelete(key)
	s.NoError(err)

	res, err = s.client.List()
	s.NoError(err)
	s.NotContains(res.Data.Keys, key)
}

func (s *TransitTestSuite) TestRotate() {
	key := "testRotate"
	err := s.client.Create(key, TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	err = s.client.Rotate(key)
	s.NoError(err)

	res, err := s.client.Read(key)
	s.NoError(err)
	s.Equal(2, res.Data.LatestVersion)

	err = s.client.ForceDelete(key)
	s.NoError(err)
}

func (s *TransitTestSuite) TestExport() {
	key := "testExport"
	err := s.client.Create(key, TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	res, err := s.client.Export(key, &TransitExportOptions{
		KeyType: "encryption-key",
	})
	s.NoError(err)
	s.NotEmpty(res.Data.Keys[1])

	err = s.client.ForceDelete(key)
	s.NoError(err)
}

func (s *TransitTestSuite) TestKeyExists() {
	err := s.client.Create("testExists", TransitCreateOptions{
		Exportable: null.BoolFrom(true),
	})
	s.NoError(err)

	res, err := s.client.KeyExists("testExists")
	s.NoError(err)
	s.True(res)

	res, err = s.client.KeyExists("testExistsNot")
	s.NoError(err)
	s.False(res)
}

func (s *TransitTestSuite) TestEncryptDecrypt() {
	err := s.client.Create("testEncryptDecrypt", TransitCreateOptions{})
	s.NoError(err)

	textb64 := "dGVzdA=="

	enc, err := s.client.Encrypt("testEncryptDecrypt", &TransitEncryptOptions{
		Plaintext: textb64,
	})
	s.NoError(err)

	dec, err := s.client.Decrpyt("testEncryptDecrypt", &TransitDecryptOptions{
		Ciphertext: enc.Data.Ciphertext,
	})
	s.NoError(err)

	s.Equal(textb64, dec.Data.Plaintext)
}

func (s *TransitTestSuite) TestEncryptDecryptBatch() {
	err := s.client.Create("testEncryptDecryptBatch", TransitCreateOptions{})
	s.NoError(err)

	text1b64 := "dGVzdA=="
	text2b64 := "Zm9v"

	enc, err := s.client.EncryptBatch("testEncryptDecryptBatch", &TransitEncryptOptionsBatch{
		BatchInput: []TransitBatchPlaintext{
			{
				Plaintext: text1b64,
			},
			{
				Plaintext: text2b64,
			},
		},
	})
	s.NoError(err)

	dec, err := s.client.DecrpytBatch("testEncryptDecryptBatch", &TransitDecryptOptionsBatch{
		BatchInput: enc.Data.BatchResults,
	})
	s.NoError(err)

	s.Equal(text1b64, dec.Data.BatchResults[0].Plaintext)
	s.Equal(text2b64, dec.Data.BatchResults[1].Plaintext)
}
