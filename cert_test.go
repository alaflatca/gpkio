package gpkio

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	dummy := GenerateDummyTLS()
	require.NotNil(t, dummy)
}
