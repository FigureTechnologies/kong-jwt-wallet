# kong-wallet-jwt

Adds an extra layer of security and functions as a RBAC authority. 
This plugin will verify a user signed JWT as a Bearer token in the `Authorization` header.
The plugin will also function as a RBAC authority and inject a `x-wallet-access` header into the request containing delegated access rights assigned to the wallet that signed the JWT.
These rights are pulled from a running instance of the RBAC service.

## Output
Wallet access header content:
```json
{
	"address": "your_wallet_address",
	"name": "your wallet name",
	"grants": [
		{
			"address": "grantor_address",
			"name": "grantor name",
			"applications": [
				{
					"name": "application_name",
					"permissions": ["list", "of", "off-chain", "application", "permissions"]
				}
			]
		}
	]
}
```

## Getting started

When using this plugin you can use `go install github.com/FigureTechnologies/kong-jwt-wallet/cmd/jwt-wallet@v0.10.0` directly or download a release version (soon to come)

### Configuration

To use the plugin, add it to your kong service definition.

Recommended configuration:
```yaml
  plugins:
  - name: jwt-wallet
    config:
      rbac: http://localhost:8888/rbac/api/v1/subjects/{addr}/grants
```

Configuration options:
* `rbac`* - Full path to your running RBAC service. The rbac url should contain an `{addr}` string representing the wallet address. If not set then the plugin will only verify a user signed JWT and will not retrieve delegated access rights or include the x-wallet-access header. 
* `apikey` - API Key to use when making a call to the RBAC service
* `authHeader` - The name of the request header containing the JWT. Defaults to "Authorization". 
  - Requires the Bearer token format e.g {authHeader} Bearer {jwt}
* `accessHeader` - The name of the header to inject with the wallet access JSON. Defaults to "x-wallet-access". Only injected when rbac configuration is set
* `senderHeader` - The name of the header to inject with the `addr` claim of the user signed JWT. If not set then will not inject
* `publicKeyHeader` - The name of the header to inject with the public key (`sub` claim) of the wallet. If not set then will not inject.

*= Required to get delegated access rights


### Running locally

Run via docker:
```bash
make docker && make docker-run
```

Use `config.yml` to update the settings for your local running environment.
Point the `rbac` url to a running copy of RBAC Service or serve the included example payload from the `http/` directory by running: 
```bash
make http
```

When using the example payload, use the value from `/token` as the JWT/Bearer token for your request.


## Creating a JWT

This example uses the standard jwt format but sings with an `secp256k1` elliptic curve key. When generating your jwt you must set the public key as the `sub` field on the payload and it must be compressed public key bytes and **Base64Url Encoded**. If wanting grants to return then also include the wallet address as the `addr` field. 

   

### Header

```json
{
  "alg": "ES256K",
  "typ": "JWT"
}
```

### Payload

```json
{
  "addr": "wallet_address",
  "sub": base64UrlEncode("wallet_public_key"),
  "iss": "your_org",
  "iat": 1609459200,
  "exp": 4070908800
}
```

### Signature

```
ecdsa.Sign(
  SHA256(base64UrlEncode(header) + "." +
  base64UrlEncode(payload)))
```

### Full token representation

```
base64UrlEncode(header) + "." +
  base64UrlEncode(payload) + "." +
    base64UrlEncode(signature)
```

