package gpkio

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

type DummyTLS struct {
	CertFile string
	KeyFile  string
}

// https://help.hcltechsw.com/domino/10.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html
func GenerateDummyTLS() *DummyTLS {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:  []string{"Company dummydummy inc."},
			Country:       []string{"KR"},
			Locality:      []string{"Seoul"},
			StreetAddress: []string{"Eo Dinga"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		IsCA:      true,
		// [ KeyUsage ]
		// 인증서와 연관된 공개키쌍의 사용목적을 정의함
		// 일반적으로 공개키쌍의 사용 용도를 제한하기 위한 목적
		// 전자서명, 부인봉쇄, 키전송, 데이터암호화, 키공유, 인증서서명, CRL서명, 키공유시 암호화 수행, 키공유시 복호화 수행 용도

		// 전자 서명 ( x509.KeyUsageDigitalSignature )
		// 공개 키가 부인 방지, 인증서 서명 또는 CRL 서명 이외의 보안 서비스를 지원하기 위해 디지털 서명 메커니즘과 함께 사용될 때 사용합니다.
		// 디지털 서명은 종종 무결성을 갖춘 엔터티 인증 및 데이터 출처 인증에 사용됩니다.

		// 인증서 서명 ( x509.KeyUsageCertSign )
		// 주체 공개 키가 인증서의 서명을 검증하는 데 사용될 때 사용합니다. 이 확장은 CA 인증서에서만 사용할 수 있습니다
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		// [ ExtKeyUsage ]
		// 인증서와 연관된 공개키쌍의 추가적인 사용목적을 정의함
		// keyUsage의 확장개념
		// 서버인증, 클라이언트인증 (SSL 인증서에서 주로 사용), 코드사인, 이메일보안, 타임스탬프, OCSP 서명, 기타 정의된 용도
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, // CA 인증서 필수 값
	}

	pki, err := GeneratePKI(&Config{
		BitSize: 4096,
	})
	if err != nil {
		panic(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pki.publicKey, pki.privateKey)
	if err != nil {
		panic(err)
	}

	caPem := new(bytes.Buffer)
	pem.Encode(caPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPemFile, err := os.Create("ca.pem")
	if err != nil {
		panic(err)
	}
	defer caPemFile.Close()

	_, err = caPemFile.Write(caPem.Bytes())
	if err != nil {
		panic(err)
	}

	caPrivKeyPem := new(bytes.Buffer)
	pem.Encode(caPrivKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pki.privateKey),
	})

	caPrivKeyPemFile, err := os.Create("key.pem")
	if err != nil {
		panic(err)
	}
	defer caPrivKeyPemFile.Close()

	_, err = caPrivKeyPemFile.Write(caPrivKeyPem.Bytes())
	if err != nil {
		panic(err)
	}

	return &DummyTLS{
		CertFile: "ca.pem",
		KeyFile:  "key.pem",
	}
}

func decodePem(path string) (*tls.Certificate, error) {
	bdata, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bdata)
	if block == nil {
		return nil, errors.New("pem decode failed")
	}

	cert := &tls.Certificate{}
	switch block.Type {
	case "CERTIFICATE":
		cert.Certificate = append(cert.Certificate, block.Bytes)
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("no certificate found in %q", path)
		}
	default:
		if cert.PrivateKey, err = parsePrivateKey(block.Bytes); err != nil {
			return nil, err
		}
		if cert.PrivateKey == nil {
			return nil, fmt.Errorf("no private key found in %q", path)
		}
	}

	return cert, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unkown private key type: %q", key)
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key")
}

func fileExists(files ...string) error {
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
