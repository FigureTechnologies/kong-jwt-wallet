package signing

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/Kong/go-pdk"
	secp256k1 "github.com/btcsuite/btcd/btcec"
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
		var keyBytes, err = base64.RawStdEncoding.DecodeString(keyB64)
		if err != nil {
			keyBytes, err = base64.RawURLEncoding.DecodeString(keyB64)
			if err != nil {
				return nil, err
			}
		}
		pubk, err := secp256k1.ParsePubKey(keyBytes, secp256k1.S256())
		if err != nil {
			return nil, err
		}
		return pubk, nil
	}
}

type secp256k1Sig struct {
}

var _ jwt.SigningMethod = (*secp256k1Sig)(nil)

func (s secp256k1Sig) Verify_deprecated(signingString, signature string, key interface{}) error {
	fmt.Printf("verify(" + signingString + "," + signature + ")")

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	sig, err := secp256k1.ParseSignature(sigBytes, secp256k1.S256())
	if err != nil {
		return fmt.Errorf("sig parse failed: %w, %x, %s, %s", err, sigBytes, signingString, signature)
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	ok := sig.Verify(hasher.Sum(nil), key.(*secp256k1.PublicKey))
	if !ok {
		return fmt.Errorf("sig verify failed")
	}
	return nil
}

func (s secp256k1Sig) Verify(signingString, signature string, key interface{}) error {
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

	if !ecdsa.Verify(pub.ToECDSA(), hasher.Sum(nil), bir, bis) {
		return fmt.Errorf("could not verify")
	}

	return nil
}

func (s secp256k1Sig) Sign(signingString string, key interface{}) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	sig, err := key.(*secp256k1.PrivateKey).Sign(hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	siggy := make([]byte, 0)
	siggy = append(siggy, sig.R.Bytes()...)
	siggy = append(siggy, sig.S.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(siggy), nil
}

func (s secp256k1Sig) Alg() string {
	return "ES256K"
}

func NewSecp256k1Signer() jwt.SigningMethod {
	return &secp256k1Sig{}
}
