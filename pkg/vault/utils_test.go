package vault

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type UtilsTestSuite struct {
	suite.Suite
}

func TestUtilsTestSuite(t *testing.T) {
	transitTestSuite := new(UtilsTestSuite)
	suite.Run(t, transitTestSuite)
}

func (s *UtilsTestSuite) TestResolvePathSingle() {
	s.Equal("test/foo/bar", resolvePath([]string{"/test", "/foo", "/bar"}))
}
func (s *UtilsTestSuite) TestResolvePathMultipleParts() {
	s.Equal("test/foo/bla/bar/bar", resolvePath([]string{"/test", "/foo/bla/bar", "/bar"}))
}
func (s *UtilsTestSuite) TestResolvePathMultipleSlashes() {
	s.Equal("test/foo/bla/bar", resolvePath([]string{"/test", "/////foo/bla/", "/bar///"}))
}
