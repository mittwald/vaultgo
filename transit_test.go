package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mittwald/vaultgo/test/testdata"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/suite"
)

type TransitTestSuite struct {
	suite.Suite
	client *Transit
}

func TestTransitTestSuite(t *testing.T) {
	for _, v := range testdata.VaultVersions {
		require.NoError(t, testdata.Init(context.Background(), v))

		t.Logf("using vault uri %v", testdata.Vault.URI())
		client, _ := NewClient(testdata.Vault.URI(), WithCaPath(""))
		client.SetToken(testdata.Vault.Token())
		transit := client.Transit()

		transitTestSuite := new(TransitTestSuite)
		transitTestSuite.client = transit

		suite.Run(t, transitTestSuite)
	}
}

func (s *TransitTestSuite) TestCreateAndRead() {
	err := s.client.Create("testCreateAndRead", &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	res, err := s.client.Read("testCreateAndRead")
	require.NoError(s.T(), err)

	s.Equal(true, res.Data.Exportable)
	s.T().Log(res.Data.Type)
}

func (s *TransitTestSuite) TestCreateAndList() {
	err := s.client.Create("testCreateAndList", &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	time.Sleep(time.Millisecond * 10)

	res, err := s.client.List()
	require.NoError(s.T(), err)

	s.Contains(res.Data.Keys, "testCreateAndList")
	s.NotContains(res.Data.Keys, "testListDoesNotExists")
}

func (s *TransitTestSuite) TestCreateListAllowDelete() {
	key := "testCreateListAllowDelete"
	err := s.client.Create(key, &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	res, err := s.client.List()
	require.NoError(s.T(), err)
	s.Contains(res.Data.Keys, key)

	err = s.client.Update(key, TransitUpdateOptions{
		DeletionAllowed: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	err = s.client.Delete(key)
	require.NoError(s.T(), err)

	res, err = s.client.List()
	require.NoError(s.T(), err)
	s.NotContains(res.Data.Keys, key)
}

func (s *TransitTestSuite) TestCreateListForceDelete() {
	key := "testCreateListForceDelete"
	err := s.client.Create(key, &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	res, err := s.client.List()
	require.NoError(s.T(), err)
	s.Contains(res.Data.Keys, key)

	err = s.client.ForceDelete(key)
	require.NoError(s.T(), err)

	res, err = s.client.List()
	require.NoError(s.T(), err)
	s.NotContains(res.Data.Keys, key)
}

func (s *TransitTestSuite) TestRotate() {
	key := "testRotate"
	err := s.client.Create(key, &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	err = s.client.Rotate(key)
	require.NoError(s.T(), err)

	res, err := s.client.Read(key)
	require.NoError(s.T(), err)
	s.Equal(2, res.Data.LatestVersion)

	err = s.client.ForceDelete(key)
	require.NoError(s.T(), err)
}

func (s *TransitTestSuite) TestExport() {
	key := "testExport"
	err := s.client.Create(key, &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	res, err := s.client.Export(key, TransitExportOptions{
		KeyType: "encryption-key",
	})
	require.NoError(s.T(), err)
	s.NotEmpty(res.Data.Keys[1])

	err = s.client.ForceDelete(key)
	require.NoError(s.T(), err)
}

func (s *TransitTestSuite) TestKeyExists() {
	err := s.client.Create("testExists", &TransitCreateOptions{
		Exportable: BoolPtr(true),
	})
	require.NoError(s.T(), err)

	res, err := s.client.KeyExists("testExists")
	require.NoError(s.T(), err)
	s.True(res)

	res, err = s.client.KeyExists("testExistsNot")
	require.NoError(s.T(), err)
	s.False(res)
}

func (s *TransitTestSuite) TestEncryptDecrypt() {
	err := s.client.Create("testEncryptDecrypt", &TransitCreateOptions{})
	require.NoError(s.T(), err)

	text := "test"

	enc, err := s.client.Encrypt("testEncryptDecrypt", &TransitEncryptOptions{
		Plaintext: text,
	})
	require.NoError(s.T(), err)

	dec, err := s.client.Decrypt("testEncryptDecrypt", &TransitDecryptOptions{
		Ciphertext: enc.Data.Ciphertext,
	})
	require.NoError(s.T(), err)

	s.Equal(text, dec.Data.Plaintext)
}

func (s *TransitTestSuite) TestEncryptDecryptBatch() {
	err := s.client.Create("testEncryptDecryptBatch", &TransitCreateOptions{})
	require.NoError(s.T(), err)

	text1 := "test1"
	text2 := "test2"

	enc, err := s.client.EncryptBatch("testEncryptDecryptBatch", &TransitEncryptOptionsBatch{
		BatchInput: []TransitBatchPlaintext{
			{
				Plaintext: text1,
			},
			{
				Plaintext: text2,
			},
		},
	})
	require.NoError(s.T(), err)

	dec, err := s.client.DecryptBatch("testEncryptDecryptBatch", TransitDecryptOptionsBatch{
		BatchInput: enc.Data.BatchResults,
	})
	require.NoError(s.T(), err)

	s.Equal(text1, dec.Data.BatchResults[0].Plaintext)
	s.Equal(text2, dec.Data.BatchResults[1].Plaintext)
}

func (s *TransitTestSuite) TestImplicitEncryptCreate() {
	_, err := s.client.Encrypt("test404", &TransitEncryptOptions{
		Plaintext: "asdf",
	})
	require.NoError(s.T(), err)
}

func (s *TransitTestSuite) TestDecryptWithoutKey() {
	_, err := s.client.Decrypt("test404", &TransitDecryptOptions{
		Ciphertext: "asdf",
	})
	s.Equal(ErrEncKeyNotFound, err)
}

func (s *TransitTestSuite) TestDecryptWithBadCipher() {
	err := s.client.Create("j7456gsegtfae", &TransitCreateOptions{})
	require.NoError(s.T(), err)

	_, err = s.client.Decrypt("j7456gsegtfae", &TransitDecryptOptions{
		Ciphertext: "nociphertext",
	})
	resErr := &api.ResponseError{}
	if errors.As(err, &resErr) {
		s.Equal(resErr.StatusCode, 400)
	} else {
		s.T().Logf("%#v", err)
		s.Fail("unexpected error type")
	}
}

func (s *TransitTestSuite) TestCreateKeyThatDoesAlreadyExist() {
	err := s.client.Create("testCeateKeyThatDoesAlreadyExist", &TransitCreateOptions{})
	require.NoError(s.T(), err)
	err = s.client.Create("testCeateKeyThatDoesAlreadyExist", &TransitCreateOptions{})
	require.NoError(s.T(), err)
}

func (s *TransitTestSuite) TestSignVerify() {
	err := s.client.Create("testSignVerify", &TransitCreateOptions{Type: "rsa-2048"})
	require.NoError(s.T(), err)

	text := "test"

	signRes, err := s.client.Sign("testSignVerify", &TransitSignOptions{
		Input: text,
	})
	require.NoError(s.T(), err)

	verifyRes, err := s.client.Verify("testSignVerify", &TransitVerifyOptions{
		Input:     text,
		Signature: signRes.Data.Signature,
	})
	require.NoError(s.T(), err)

	s.True(verifyRes.Data.Valid)
}

func (s *TransitTestSuite) TestSignVerifyBatch() {
	err := s.client.Create("testSignVerify", &TransitCreateOptions{Type: "rsa-2048"})
	require.NoError(s.T(), err)

	text1 := "test1"
	text2 := "test2"

	signRes, err := s.client.SignBatch("testSignVerify", &TransitSignOptionsBatch{
		BatchInput: []TransitBatchSignInput{
			{Input: text1},
			{Input: text2},
		},
	})
	require.NoError(s.T(), err)

	verifyRes, err := s.client.VerifyBatch("testSignVerify", &TransitVerifyOptionsBatch{
		BatchInput: []TransitBatchVerifyInput{
			{Input: text1, Signature: signRes.Data.BatchResults[0].Signature},
			{Input: text2, Signature: signRes.Data.BatchResults[1].Signature},
		},
	})
	require.NoError(s.T(), err)

	s.True(verifyRes.Data.BatchResults[0].Valid)
	s.True(verifyRes.Data.BatchResults[1].Valid)
}

func (s *TransitTestSuite) TestDecodeCipherText() {
	dec, ver, err := DecodeCipherText("vault:v123:SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	require.NoError(s.T(), err)
	s.Equal("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", dec)
	s.Equal(123, ver)
}

func (s *TransitTestSuite) TestDecodeCipherTextError() {
	_, _, err := DecodeCipherText("vault:SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	s.NotNil(err)
}

func (s *TransitTestSuite) TestEncodeCipherText() {
	enc := EncodeCipherText("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 123)
	s.Equal("vault:v123:SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", enc)
}
