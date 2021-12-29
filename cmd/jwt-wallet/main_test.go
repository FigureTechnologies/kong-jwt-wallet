package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/Kong/go-pdk/test"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/golang-jwt/jwt/v4"
	jwtwallet "github.com/provenance-io/kong-jwt-wallet"
	"github.com/provenance-io/kong-jwt-wallet/grants"
	"github.com/provenance-io/kong-jwt-wallet/signing"
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
	prvk, pubk := secp256k1.PrivKeyFromBytes(secp256k1.S256(), pkBytes)

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
}

func TestMissingSubClaim(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), pkBytes)

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

func TestValidJwt(t *testing.T) {
	pkBytes, _ := hex.DecodeString("8C037EFC21AB3F0F8D32CF209D90FDBF41D10071FF600BA66A30EFA994F268A3")
	prvk, pubk := secp256k1.PrivKeyFromBytes(secp256k1.S256(), pkBytes)

	claims := GenerateClaims("tbMadeUpAddr", pubk)
	token := jwt.NewWithClaims(signing.NewSecp256k1Signer(), claims)
	sig, _ := token.SignedString(prvk)

	r := ioutil.NopCloser(bytes.NewReader([]byte(grantsJSONString)))
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

	env.DoHttp(config)

	assert.Equal(t, 200, env.ClientRes.Status)
	assert.NotEmpty(t, env.ServiceReq.Headers.Get("x-roles"))
	assert.Equal(t, xRoles, env.ServiceReq.Headers.Get("x-roles"))
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

var grantsJSONString = `
{
	"account": {
		"address": "1337-wallet",
		"name": "jwt-wallet",
		"type": "ORGANIZATION"
	},
	"grants": [
		{
			"org": {
				"address": "1337-wallet",
				"name": "jwt-wallet",
				"type": "ORGANIZATION"
			},
			"roles": [
				"1337_role"
			],
			"authzGrants": [],
			"apps": []
		}
	]
}`

var xRoles = `{"orgs":[{"name":"jwt-wallet","roles":["1337_role"],"authzGrants":[]}]}`