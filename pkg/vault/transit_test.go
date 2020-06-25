package vault

import (
	"fmt"
	"testing"
	"time"

	hcvault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/suite"
	"gopkg.in/guregu/null.v3"
)

type TransitTestSuite struct {
	suite.Suite
	client *Transit
}

func TestTransitTestSuite(t *testing.T) {
	client, _ := NewClient("http://localhost:8200/", WithCaPath(""))
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

	time.Sleep(time.Millisecond * 10)

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

	err = s.client.Update(key, TransitUpdateOptions{
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

	res, err := s.client.Export(key, TransitExportOptions{
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

	text := "test"

	enc, err := s.client.Encrypt("testEncryptDecrypt", TransitEncryptOptions{
		Plaintext: text,
	})
	s.NoError(err)

	dec, err := s.client.Decrypt("testEncryptDecrypt", TransitDecryptOptions{
		Ciphertext: enc.Data.Ciphertext,
	})
	s.NoError(err)

	s.Equal(text, dec.Data.Plaintext)
}

func (s *TransitTestSuite) TestEncryptDecryptBatch() {
	err := s.client.Create("testEncryptDecryptBatch", TransitCreateOptions{})
	s.NoError(err)

	text1 := "test1"
	text2 := "test2"

	enc, err := s.client.EncryptBatch("testEncryptDecryptBatch", TransitEncryptOptionsBatch{
		BatchInput: []TransitBatchPlaintext{
			{
				Plaintext: text1,
			},
			{
				Plaintext: text2,
			},
		},
	})
	s.NoError(err)

	dec, err := s.client.DecryptBatch("testEncryptDecryptBatch", TransitDecryptOptionsBatch{
		BatchInput: enc.Data.BatchResults,
	})
	s.NoError(err)

	s.Equal(text1, dec.Data.BatchResults[0].Plaintext)
	s.Equal(text2, dec.Data.BatchResults[1].Plaintext)
}

func (s *TransitTestSuite) TestDecryptWithoutKey() {
	_, err := s.client.Decrypt("test404", TransitDecryptOptions{
		Ciphertext: "asdf",
	})
	s.Equal(ErrEncKeyNotFound, err)
}

func (s *TransitTestSuite) TestDecryptWithBadCipher() {
	err := s.client.Create("j7456gsegtfae", TransitCreateOptions{})
	s.NoError(err)

	_, err = s.client.Decrypt("j7456gsegtfae", TransitDecryptOptions{
		Ciphertext: "nociphertext",
	})
	resErr, ok := err.(*hcvault.ResponseError)
	if ok {
		fmt.Println(resErr)
		s.Equal(resErr.StatusCode, 400)
	} else {
		s.Fail("unexpected error type")
	}
}

func (s *TransitTestSuite) TestCreateKeyThatDoesAlreadyExist() {
	err := s.client.Create("testCeateKeyThatDoesAlreadyExist", TransitCreateOptions{})
	s.NoError(err)
	err = s.client.Create("testCeateKeyThatDoesAlreadyExist", TransitCreateOptions{})
	s.NoError(err)
}
