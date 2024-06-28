# gpkio
Go PKI

## Install
```
go get -u github.com/alaflatca/gpkio
```

## Generate
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

## Encrypt
```
encryptedData, err := pki.Encrypt([]byte("Hello, gpkio!"))
```

## Decrypt
```
decryptedData, err := pki.Decrypt(encryptedData)
```

## Sign
```
base64Signature, err := pki.Sign([]byte("Hello, gpkio!"))
```

## Verify
```
digest := []byte("Hello, gpkio!")
base64Signature, err := pki.Sign(digest)
err := pki.Verifiy(digest, base64Signature)
```

## Hash
```
hashSum, err := pki.Hash([]byte("Hello, gpkio!"))
```

## Remove
```
err := pki.Remove()
```
