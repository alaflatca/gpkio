package gpkio

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKI(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T, pki *PKI){
		"Generate Key":    testGenerateKey,
		"Encrypt/Decrypt": testEncryptDecrypt,
		"Sign/Verify":     testSignVerify,
	} {
		t.Run(scenario, func(t *testing.T) {
			pki := setup(t)
			defer pki.Remove()
			fn(t, pki)
		})
	}
}

func setup(t *testing.T) *PKI {
	pki, err := GenerateKey(&Config{
		Dir:     "keys",
		BitSize: 2048,
	})
	require.NoError(t, err)
	return pki
}

func testGenerateKey(t *testing.T, pki *PKI) {
	fi, err := os.Stat(pki.cfg.PrivateKeyFileName)
	require.NoError(t, err)
	require.Equal(t, fi.Name(), "private.pem")

	fi, err = os.Stat(pki.cfg.PublicKeyFileName)
	require.NoError(t, err)
	require.Equal(t, fi.Name(), "public.pem")
}

func testEncryptDecrypt(t *testing.T, pki *PKI) {
	data := []byte("Hello, gpkio!")

	encryptData, err := pki.Encrypt(data)
	require.NoError(t, err)
	require.NotEqual(t, encryptData, data)

	decryptData, err := pki.Decrypt(encryptData)
	require.NoError(t, err)
	require.Equal(t, data, decryptData)
}

func testSignVerify(t *testing.T, pki *PKI) {
	signData := []byte("gpkio is library")

	base64Signature, err := pki.Sign(signData)
	require.NoError(t, err)

	err = pki.Verifiy(signData, base64Signature)
	require.NoError(t, err)
}
