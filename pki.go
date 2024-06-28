package gpkio

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

type PKI struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	cfg        *Config
}

type Config struct {
	Dir                string // default ./
	PrivateKeyFileName string // default private.pem
	PublicKeyFileName  string // default public.pem
	BitSize            int    // default 2048
}

func (c *Config) check() {
	if c.Dir == "" {
		c.Dir = "./"
	} else {
		directoryCheck(c.Dir)
	}
	if c.BitSize == 0 {
		c.BitSize = 2048
	}
	if c.PrivateKeyFileName == "" {
		c.PrivateKeyFileName = "private"
	}
	if c.PublicKeyFileName == "" {
		c.PublicKeyFileName = "public"
	}

	c.PrivateKeyFileName = filepath.Join(c.Dir, fmt.Sprintf("%s%s", c.PrivateKeyFileName, ".pem"))
	c.PublicKeyFileName = filepath.Join(c.Dir, fmt.Sprintf("%s%s", c.PublicKeyFileName, ".pem"))
}

// PKCS#1 RSA 암호화 표준
// PKIX 공개 키 인증서 형식 정의
func GenerateKey(cfg *Config) (*PKI, error) {
	cfg.check()

	//===== private key =====
	private, err := rsa.GenerateKey(rand.Reader, cfg.BitSize)
	if err != nil {
		return nil, errors.Wrap(err, "GenerateKey()")
	}
	public := &private.PublicKey

	pemPrivateKey, err := os.Create(cfg.PrivateKeyFileName)
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
	pemPublicKey, err := os.Create(cfg.PublicKeyFileName)
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
		cfg:        cfg,
	}

	return pki, nil
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
	hashData, err := p.Hash(data)
	if err != nil {
		return "", errors.Wrap(err, "Hash()")
	}

	signature, err := rsa.SignPSS(rand.Reader, p.privateKey, crypto.SHA256, hashData, nil)
	if err != nil {
		return "", errors.Wrap(err, "SignPSS()")
	}

	b64signature := base64.StdEncoding.EncodeToString(signature)
	return b64signature, nil
}

func (p *PKI) Verifiy(digest []byte, base64Signature string) error {
	hashDigest, err := p.Hash(digest)
	if err != nil {
		return errors.Wrap(err, "Hash()")
	}

	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return errors.Wrap(err, "Base64DecodeString()")
	}

	err = rsa.VerifyPSS(p.publicKey, crypto.SHA256, hashDigest, signature, nil)
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
	if _, err := os.Stat(p.cfg.PrivateKeyFileName); !os.IsNotExist(err) {
		// key exist
		if err := os.Remove(p.cfg.PrivateKeyFileName); err != nil {
			return err
		}
	}
	if _, err := os.Stat(p.cfg.PublicKeyFileName); !os.IsNotExist(err) {
		// key exist
		if err := os.Remove(p.cfg.PublicKeyFileName); err != nil {
			return err
		}
	}
	return nil
}

func directoryCheck(dirName string) {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		if err = os.Mkdir(dirName, 0700); err != nil {
			panic(err)
		}
	}
}
