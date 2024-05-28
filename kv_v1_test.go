package vault_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	vault "github.com/mittwald/vaultgo"
	"github.com/mittwald/vaultgo/test/testdata"

	"github.com/stretchr/testify/suite"
)

type KVv1TestSuite struct {
	suite.Suite
	client *vault.KVv1
}

func TestKVv1TestSuite(t *testing.T) {
	for _, v := range testdata.VaultVersions {
		require.NoError(t, testdata.Init(context.Background(), v))

		t.Logf("using vault uri %v", testdata.Vault.URI())
		client, _ := vault.NewClient(testdata.Vault.URI(), vault.WithCaPath(""))
		client.SetToken(testdata.Vault.Token())
		keyValue := client.KVv1()

		keyValueTestSuite := new(KVv1TestSuite)
		keyValueTestSuite.client = keyValue

		suite.Run(t, keyValueTestSuite)
	}
}

func (s *KVv1TestSuite) TestCreateAndRead() {
	testKeyValues := make(map[string]string)
	testKeyValues["PrivateKey"] = "abcde"

	err := s.client.Create("9697fdce-39df-45ac-9115-5e3913c34613", testKeyValues)
	require.NoError(s.T(), err)

	readResponse, readErr := s.client.Read("9697fdce-39df-45ac-9115-5e3913c34613")
	require.NoError(s.T(), readErr)

	require.Equal(s.T(), readResponse.Data, testKeyValues)
}

func (s *KVv1TestSuite) TestOverwriteAndRead() {
	testKeyValues := make(map[string]string)
	testKeyValues["PrivateKey"] = "abcde"
	testKeyValues["PrivateKey2"] = "fghji"

	err := s.client.Create("9697fdce-39df-45ac-9115-5e3913c34613", testKeyValues)
	require.NoError(s.T(), err)

	testKeyValuesNew := make(map[string]string)
	testKeyValuesNew["PrivateKey"] = "klmnop"

	err = s.client.Create("9697fdce-39df-45ac-9115-5e3913c34613", testKeyValuesNew)
	require.NoError(s.T(), err)

	readResponse, readErr := s.client.Read("9697fdce-39df-45ac-9115-5e3913c34613")
	require.NoError(s.T(), readErr)

	require.Equal(s.T(), readResponse.Data, testKeyValuesNew)
}

func (s *KVv1TestSuite) TestCreateAndDelete() {
	testKeyValues := make(map[string]string)
	testKeyValues["PrivateKey"] = "abcde"

	err := s.client.Create("2b7ff26d-30b7-43ba-96d5-79b4baba9b39", testKeyValues)
	require.NoError(s.T(), err)

	deleteErr := s.client.Delete("2b7ff26d-30b7-43ba-96d5-79b4baba9b39")
	require.NoError(s.T(), deleteErr)

	_, readErr := s.client.Read("2b7ff26d-30b7-43ba-96d5-79b4baba9b39")
	require.Error(s.T(), readErr)
}
