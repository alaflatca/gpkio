# gpkio
- PKI, A simple PKI library made of Golang
- DummyTLS, Dummy TLS for easy testing of HTTPS web servers ( certFile, KeyFile )
  
# Install
```
go get -u github.com/alaflatca/gpkio
```

## DummyTLS ( HTTPS Web Server Simple Test )
```
dummy := gpkio.GenerateDummyTLS()
http.ListenAndServeTLS(":443", dummy.CertFile, dummy.KeyFile, nil)
```

## PKI
### Generate
```
pki, err := gpkio.GenerateKey(&gpkio.Config{
    Dir:                "keys",          // default "./"
    PrivateKeyFileName: "private-key",   // default "private"
    PublicKeyFileName:  "public-key",    // default "public"
    BitSize:            2048,            // default "2048"
})

==> ./keys/private-key.pem
==> ./keys/public-key.pem
```

### Load
```
privateKey, publicKey, err := pki.LoadKey(pki.config.PrivateKeyFileName, pki.config.PublicKeyFileName)
```

### Encrypt
```
encryptedData, err := pki.Encrypt([]byte("Hello, gpkio!"))
```

### Decrypt
```
decryptedData, err := pki.Decrypt(encryptedData)
```

### Sign
```
base64Signature, err := pki.Sign([]byte("Hello, gpkio!"))
```

### Verify
```
origin := []byte("Hello, gpkio!")
base64Signature, err := pki.Sign(origin)
err := pki.Verifiy(origin, base64Signature)
```

### Hash
```
hashData, err := pki.Hash([]byte("Hello, gpkio!"))
```

### Remove
```
err := pki.Remove()
```
