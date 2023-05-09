package signing

import (
	goecdsa "crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"reflect"
	"strings"

	"github.com/Kong/go-pdk"
	ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Addr string `json:"addr"`
	jwt.RegisteredClaims
}

func init() {
	jwt.RegisterSigningMethod("ES256K", NewSecp256k1Signer)
}

func ParseKey(kong *pdk.PDK) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(*Claims)
		if !ok {
			if kong != nil {
				kong.Log.Warn("no claims")
			}
			return nil, fmt.Errorf("no claims")
		}
		sub := claims.RegisteredClaims.Subject
		if sub == "" {
			if kong != nil {
				kong.Log.Warn("no subject")
			}
			return nil, fmt.Errorf("no subject")
		}
		keyB64 := strings.Split(sub, ",")[0]
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, err
		}
		pubk, err := secp256k1.ParsePubKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return pubk, nil
	}
}

type secp256k1Sig struct {
}

var _ jwt.SigningMethod = (*secp256k1Sig)(nil)

func (t secp256k1Sig) Verify_deprecated(signingString, signature string, key interface{}) error {
	fmt.Printf("verify(" + signingString + "," + signature + ")")

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	sig, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("sig parse failed: %w, %x, %s, %s", err, sigBytes, signingString, signature)
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	ok := sig.Verify(hasher.Sum(nil), key.(*btcec.PublicKey))
	if !ok {
		return fmt.Errorf("sig verify failed")
	}
	return nil
}

func (t secp256k1Sig) Verify(signingString, signature string, key interface{}) error {
	pub, ok := key.(*secp256k1.PublicKey)
	if !ok {
		fmt.Println("Wrong fromat")
		return fmt.Errorf("wrong key format")
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	if len(sig) != 64 {
		return fmt.Errorf("bad signature")
	}

	bir := new(big.Int).SetBytes(sig[:32])   // R
	bis := new(big.Int).SetBytes(sig[32:64]) // S

	if !goecdsa.Verify(pub.ToECDSA(), hasher.Sum(nil), bir, bis) {
		return fmt.Errorf("could not verify")
	}

	return nil
}

func (t secp256k1Sig) Sign(signingString string, key interface{}) (string, error) {
	pkey, ok := key.(*btcec.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected btcec.PrivateKey, found %s", reflect.TypeOf(key))
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	r, s, err := goecdsa.Sign(crand.Reader, pkey.ToECDSA(), hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	siggy := make([]byte, 0)
	siggy = append(siggy, r.Bytes()...)
	siggy = append(siggy, s.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(siggy), nil
}

func (t secp256k1Sig) Alg() string {
	return "ES256K"
}

func NewSecp256k1Signer() jwt.SigningMethod {
	return &secp256k1Sig{}
}
