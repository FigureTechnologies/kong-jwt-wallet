package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	jwtwallet "github.com/FigureTechnologies/kong-jwt-wallet"
	"github.com/FigureTechnologies/kong-jwt-wallet/grants"
	"github.com/FigureTechnologies/kong-jwt-wallet/signing"
	"github.com/Kong/go-pdk/test"
	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

var (
	GetDoFunc func(req *http.Request) (*http.Response, error)
)

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return GetDoFunc(req)
}

var config = &jwtwallet.Config{
	RBAC: "localhost:2000",
}

func init() {
	grants.Client = &MockClient{}

}

func TestMissingAuthHeader(t *testing.T) {
	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com",
	})
	assert.NoError(t, err)

	env.DoHttp(config)

	assert.Equal(t, 401, env.ClientRes.Status)
}

func TestInvalidJwt(t *testing.T) {
	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"not-a-valid-jwt"}},
	})
	assert.NoError(t, err)

	env.DoHttp(config)

	assert.Equal(t, 401, env.ClientRes.Status)
}

func TestMissingAddrClaim(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, pubk := secp256k1.PrivKeyFromBytes(pkBytes)

	claims := GenerateClaims("", pubk)
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + sig}},
	})
	assert.NoError(t, err)

	env.DoHttp(config)

	assert.Equal(t, 400, env.ClientRes.Status)
	assert.Equal(t, "missing addr claim", env.ClientRes.Body)
}

func TestMissingSubClaim(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, _ := secp256k1.PrivKeyFromBytes(pkBytes)

	claims := GenerateClaims("tbMadeUpAddr", nil)
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + sig}},
	})
	assert.NoError(t, err)

	env.DoHttp(config)

	assert.Equal(t, 401, env.ClientRes.Status)
}

func TestExpiredToken(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, pubk := secp256k1.PrivKeyFromBytes(pkBytes)

	claims := GenerateClaims("tb1MadeUpAddr", pubk)
	claims.ExpiresAt = jwt.NewNumericDate(time.Date(1999, 12, 31, 11, 10, 0, 0, time.Local))
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + sig}},
	})
	assert.NoError(t, err)

	env.DoHttp(config)

	assert.Equal(t, 401, env.ClientRes.Status)
}

func TestValidJwt(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, pubk := secp256k1.PrivKeyFromBytes(pkBytes)
	claims := GenerateClaims("tp1y34frcm3hmnmgszmnxufcyw4aeslplsz8hkuxv", pubk)
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	r := ioutil.NopCloser(bytes.NewReader([]byte(subjectJSONString)))
	GetDoFunc = func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       r,
		}, nil
	}

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + sig}},
	})
	assert.NoError(t, err)

	config.PublicKeyHeader = "x-wallet-public-key"
	env.DoHttp(config)

	assert.Equal(t, 200, env.ClientRes.Status)
	assert.NotEmpty(t, env.ServiceReq.Headers.Get("x-wallet-access"))
	assert.Equal(t, env.ServiceReq.Headers.Get("x-wallet-public-key"), claims.Subject)
	assert.Empty(t, env.ServiceReq.Headers.Get("x-sender"))
	assert.Equal(t, subjectJSONString, env.ServiceReq.Headers.Get("x-wallet-access"))
}

func TestValidJwtWithEmptyRbacUrl(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, pubk := secp256k1.PrivKeyFromBytes(pkBytes)
	addr := "tp1y34frcm3hmnmgszmnxufcyw4aeslplsz8hkuxv"
	claims := GenerateClaims(addr, pubk)
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + sig}, "x-sender": {"test"}},
	})
	assert.NoError(t, err)

	var emptyRBACUrlConfig = &jwtwallet.Config{
		SenderHeader: "x-sender",
	}
	env.DoHttp(emptyRBACUrlConfig)

	assert.Equal(t, 200, env.ClientRes.Status)
	assert.NotEmpty(t, env.ServiceReq.Headers.Get("x-sender"))
	assert.Empty(t, env.ServiceReq.Headers.Get("x-wallet-access"))
	assert.Equal(t, addr, env.ServiceReq.Headers.Get("x-sender"))
}

func TestIncorrectAddress(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, pubk := secp256k1.PrivKeyFromBytes(pkBytes)

	claims := GenerateClaims("tp1rr4d0eu62pgt4edw38d2ev27798pfhdhp5ttha", pubk)
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + sig}},
	})
	assert.NoError(t, err)

	env.DoHttp(config)

	assert.Equal(t, 400, env.ClientRes.Status)
	assert.Contains(t, env.ClientRes.Body, "address does not match public key")
}

func GenerateClaims(addr string, pubKey *secp256k1.PublicKey) *signing.Claims {
	compressedKey := ""
	if pubKey != nil {
		compressedKey = base64.RawURLEncoding.EncodeToString(pubKey.SerializeCompressed())
	}
	loc, _ := time.LoadLocation("GMT")
	return &signing.Claims{
		Addr: addr,
		RegisteredClaims: *&jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Date(2099, 1, 1, 0, 0, 0, 0, loc)),
			IssuedAt:  jwt.NewNumericDate(time.Date(2021, 1, 1, 0, 0, 0, 0, loc)),
			Issuer:    "provenance.io",
			Subject:   compressedKey,
		},
	}
}

var subjectJSONString = `{"address":"1337-wallet","name":"jwt-wallet","grants":[{"address":"1337-wallet","name":"jwt-wallet","applications":[{"name":"myapp","permissions":["1337_role"]}]}]}`
