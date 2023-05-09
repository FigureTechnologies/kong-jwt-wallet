package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/golang-jwt/jwt/v4"

	"github.com/FigureTechnologies/kong-jwt-wallet/signing"
)

func main() {
	pkBytes, err := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	if err != nil {
		panic(err)
	}
	prvk, pubk := secp256k1.PrivKeyFromBytes(pkBytes)
	fmt.Printf("prvKey:%X\n", prvk.Serialize())
	fmt.Printf("pubKey:%X\n", pubk.SerializeCompressed())

	loc, err := time.LoadLocation("GMT")
	if err != nil {
		panic(err)
	}

	claims := &signing.Claims{
		Addr: "tp1uz5g72pvfrdnm9qnjpyvsnwc64d4wygyqanx2t",
		RegisteredClaims: *&jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Date(2099, 1, 1, 0, 0, 0, 0, loc)),
			IssuedAt:  jwt.NewNumericDate(time.Date(2021, 1, 1, 0, 0, 0, 0, loc)),
			Issuer:    "tech.figure",
			Subject:   base64.RawURLEncoding.EncodeToString(pubk.SerializeCompressed()),
		},
	}

	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, err := token.SignedString(prvk)
	fmt.Printf("signed:%s\n", sig)

	var newClaims signing.Claims
	newToken, err := jwt.ParseWithClaims(sig, &newClaims, signing.ParseKey(nil))

	fmt.Printf("sig:%s\n", newToken.Signature)
	fmt.Printf("valid:%+v\n", newToken)
}
