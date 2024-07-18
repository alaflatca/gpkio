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
	config     *Config
}

type Config struct {
	Dir                string // default ./
	PrivateKeyFileName string // default private.pem
	PublicKeyFileName  string // default public.pem
	BitSize            int    // default 2048
	NotSave            bool
}

func (c *Config) check() {
	if c.Dir == "" {
		c.Dir = "./"
	}

	if _, err := os.Stat(c.Dir); os.IsNotExist(err) {
		if err = os.Mkdir(c.Dir, 0700); err != nil {
			panic(err)
		}
	}

	if c.BitSize == 0 {
		c.BitSize = 2048
	}
	if c.PrivateKeyFileName == "" {
		c.PrivateKeyFileName = "key"
	}
	if c.PublicKeyFileName == "" {
		c.PublicKeyFileName = "pub"
	}

	c.PrivateKeyFileName = filepath.Join(c.Dir, fmt.Sprintf("%s%s", c.PrivateKeyFileName, ".pem"))
	c.PublicKeyFileName = filepath.Join(c.Dir, fmt.Sprintf("%s%s", c.PublicKeyFileName, ".pem"))
}

// PKCS#1 RSA 암호화 표준
// PKIX 공개 키 인증서 형식 정의
func GeneratePKI(config *Config) (*PKI, error) {
	config.check()

	//===== private key =====
	private, err := rsa.GenerateKey(rand.Reader, config.BitSize)
	if err != nil {
		return nil, errors.Wrap(err, "GenerateKey()")
	}
	public := &private.PublicKey

	if !config.NotSave {
		pemPrivateKey, err := os.Create(config.PrivateKeyFileName)
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
	}

	//===== public key =====
	if !config.NotSave {
		pemPublicKey, err := os.Create(config.PublicKeyFileName)
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
	}

	pki := &PKI{
		privateKey: private,
		publicKey:  public,
		config:     config,
	}

	return pki, nil
}

func (p *PKI) LoadKey(privateKeyPath, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return nil, nil, err
	}
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return nil, nil, err
	}

	// private
	privatePemBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	privateBlock, _ := pem.Decode(privatePemBytes)
	if privateBlock == nil {
		return nil, nil, fmt.Errorf("%q decode fail", privateKeyPath)
	}
	if privateBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("not the rsa private key type: %q", privateBlock.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// public
	publicPemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	publicBlock, _ := pem.Decode(publicPemBytes)
	if publicBlock == nil {
		return nil, nil, fmt.Errorf("%q decode fail", publicKeyPath)
	}
	if publicBlock.Type != "RSA PUBLIC KEY" {
		return nil, nil, fmt.Errorf("not the rsa public key type: %q", publicBlock.Type)
	}
	pubKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("interface {} is not *rsa.PublicKey")
	}

	return privateKey, publicKey, nil
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

func (p *PKI) Verifiy(origin []byte, base64Signature string) error {
	hashDigest, err := p.Hash(origin)
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
	if _, err := os.Stat(p.config.PrivateKeyFileName); !os.IsNotExist(err) {
		// key exist
		if err := os.Remove(p.config.PrivateKeyFileName); err != nil {
			return err
		}
	}
	if _, err := os.Stat(p.config.PublicKeyFileName); !os.IsNotExist(err) {
		// key exist
		if err := os.Remove(p.config.PublicKeyFileName); err != nil {
			return err
		}
	}
	return nil
}

func (p *PKI) GenerateCert(template, parent *x509.Certificate, pub rsa.PublicKey, priv rsa.PrivateKey) {
	x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
}
