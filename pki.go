package gpkio

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

type PKI struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	files      []string
}

func (p *PKI) Encrypt(data []byte) ([]byte, error) {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, p.publicKey, data, nil)
	if err != nil {
		return nil, errors.Wrap(err, "EncryptOAEP()")
	}
	return encryptedData, nil
}

func (p *PKI) Decrypt(data []byte) ([]byte, error) {
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.privateKey, data, nil)
	if err != nil {
		return nil, errors.Wrap(err, "DecryptOAEP()")
	}
	return decryptedData, nil
}

func (p *PKI) Sign(data []byte) (string, error) {
	dataHash, err := p.Hash(data)
	if err != nil {
		return "", errors.Wrap(err, "Hash()")
	}

	signature, err := rsa.SignPSS(rand.Reader, p.privateKey, crypto.SHA256, dataHash, nil)
	if err != nil {
		return "", errors.Wrap(err, "SignPSS()")
	}

	b64signature := base64.StdEncoding.EncodeToString(signature)
	return b64signature, nil
}

func (p *PKI) Verifiy(digest []byte, base64Signature string) error {
	digestHash, err := p.Hash(digest)
	if err != nil {
		return errors.Wrap(err, "Hash()")
	}

	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return errors.Wrap(err, "Base64DecodeString()")
	}

	err = rsa.VerifyPSS(p.publicKey, crypto.SHA256, digestHash, signature, nil)
	if err != nil {
		return errors.Wrap(err, "VerifyPSS()")
	}

	return nil
}

func (p *PKI) Hash(data []byte) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (p *PKI) Remove() error {
	for _, file := range p.files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			continue
		}
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	return nil
}

// PKCS#1 RSA 암호화 표준
// PKIX 공개 키 인증서 형식 정의
func GenerateKey(dir string, bitSize int) (*PKI, error) {
	directoryCheck(dir)

	//===== private key =====
	private, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, errors.Wrap(err, "GenerateKey()")
	}
	public := &private.PublicKey

	privateKeyFileName := filepath.Join(dir, "private.pem")
	pemPrivateKey, err := os.Create(privateKeyFileName)
	if err != nil {
		return nil, errors.Wrap(err, "Private Create()")
	}
	defer pemPrivateKey.Close()

	pemPrivateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	}
	if err := pem.Encode(pemPrivateKey, pemPrivateBlock); err != nil {
		return nil, errors.Wrap(err, "private Encode()")
	}

	//===== public key =====
	publicKeyFileName := filepath.Join(dir, "public.pem")
	pemPublicKey, err := os.Create(publicKeyFileName)
	if err != nil {
		return nil, errors.Wrap(err, "public Create()")
	}
	defer pemPublicKey.Close()

	publicBytes, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, errors.Wrap(err, "MarshalPKIX()")
	}

	pemPublicBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicBytes,
	}
	if err := pem.Encode(pemPublicKey, pemPublicBlock); err != nil {
		return nil, errors.Wrap(err, "public Encode()")
	}

	pki := &PKI{
		privateKey: private,
		publicKey:  public,
		files:      []string{privateKeyFileName, publicKeyFileName},
	}

	return pki, nil
}

func directoryCheck(dirName string) {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		if err = os.Mkdir(dirName, 0700); err != nil {
			panic(err)
		}
	}
}
