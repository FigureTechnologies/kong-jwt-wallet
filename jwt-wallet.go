package jwtwallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"

	"github.com/FigureTechnologies/kong-jwt-wallet/grants"
	"github.com/FigureTechnologies/kong-jwt-wallet/signing"
	"github.com/cosmos/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"

	"github.com/Kong/go-pdk"
	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	RBAC            string `json:"rbac"`
	APIKey          string `json:"apikey"`
	AuthHeader      string `json:"authHeader"`
	AccessHeader    string `json:"accessHeader"`
	SenderHeader    string `json:"senderHeader"`
	PublicKeyHeader string `json:"publicKeyHeader"`
}

func New() interface{} {
	return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
	defer func() {
		err := recover()
		if err != nil {
			e, ok := err.(error)
			if ok {
				kong.Log.Err(e.Error())
				kong.Response.Exit(500, "{}", map[string][]string{})
			} else {
				kong.Log.Err(fmt.Sprintf("%v", err))
				kong.Response.Exit(500, "{}", map[string][]string{})
			}
		}
	}()

	x := make(map[string][]string)
	x["Content-Type"] = []string{"application/json"}

	if conf.AuthHeader == "" {
		conf.AuthHeader = "Authorization"
	}
	header, err := kong.Request.GetHeader(conf.AuthHeader)
	if err != nil {
		kong.Log.Warn("missing auth header")
		kong.Response.Exit(401, "{}", x)
		return
	}

	authToken := strings.Split(header, "Bearer")
	if len(authToken) < 2 {
		kong.Log.Warn("malformed auth header")
		kong.Response.Exit(401, "{}", x)
		return
	}

	tok, err := handleToken(kong, strings.TrimSpace(authToken[1]))
	if err != nil {
		kong.Log.Warn("err: " + err.Error())
		kong.Response.Exit(401, "{}", x)
		return
	}

	access, sender, err := handleGrantedAccess(tok, conf.RBAC, conf.APIKey, kong)
	if err != nil {
		kong.Log.Warn("err: " + err.Error())
		kong.Response.Exit(400, err.Error(), x)
		return
	}

	accessJson, err := json.Marshal(access)
	if err != nil {
		kong.Response.Exit(500, "something went wrong", x)
		return
	}

	if conf.AccessHeader == "" {
		conf.AccessHeader = "x-wallet-access"
	}

	if conf.RBAC != "" {
		kong.ServiceRequest.SetHeader(conf.AccessHeader, string(accessJson))
	}

	if conf.SenderHeader != "" {
		kong.ServiceRequest.SetHeader(conf.SenderHeader, sender)
	}

	if conf.PublicKeyHeader != "" {
		kong.ServiceRequest.SetHeader(conf.PublicKeyHeader, tok.Claims.(*signing.Claims).Subject)
	}

	kong.Log.Warn(tok)

}

var parser = jwt.NewParser()

func handleGrantedAccess(token *jwt.Token, url string, apiKey string, kong *pdk.PDK) (*grants.SubjectResponse, string, error) {
	claims, ok := token.Claims.(*signing.Claims)
	if !ok {
		return nil, "", fmt.Errorf("malformed claims")
	}
	if claims.Addr == "" {
		return nil, "", fmt.Errorf("missing addr claim")
	}
	if err := verifyAddress(claims.Addr, claims.Subject); err != nil {
		return nil, "", fmt.Errorf("address does not match public key: %w", err)
	}
	if url == "" {
		return nil, claims.Addr, nil
	}
	subjectResponse, err := grants.GetGrants(url, claims.Addr, apiKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get grants: %w", err)
	}
	return subjectResponse, claims.Addr, nil
}

func handleToken(kong *pdk.PDK, tokenString string) (*jwt.Token, error) {
	var claims signing.Claims
	token, err := parser.ParseWithClaims(tokenString, &claims, signing.ParseKey(kong))
	if err != nil {
		if kong != nil {
			kong.Log.Warn("parse error:" + err.Error())
		}
		return nil, err
	}
	return token, nil
}

func verifyAddress(addr string, pubKey string) error {
	separator := strings.LastIndex(addr, "1")
	if separator < 0 {
		return fmt.Errorf("address missing `1` separator")
	}

	hrp := addr[0:separator]
	keyB64 := strings.Split(pubKey, ",")[0]
	keyBytes, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		return fmt.Errorf("failed to url decode key: %w", err)
	}

	hash160Bytes := Hash160(keyBytes)
	dataBits, err := bech32.ConvertBits(hash160Bytes, 8, 5, true)
	if err != nil {
		return fmt.Errorf("failed to convert bits: %w", err)
	}

	pubKeyAddr, err := bech32.Encode(hrp, dataBits)
	if err != nil {
		return fmt.Errorf("failed to bech32 encode addr: %w", err)
	}

	eq := strings.EqualFold(addr, pubKeyAddr)
	if !eq {
		return fmt.Errorf("addr invalid: %s != %s", addr, pubKeyAddr)
	}
	return nil
}

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}
