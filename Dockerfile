FROM golang:1.17-alpine as build
RUN apk --no-cache --update add build-base
ADD . /app/
WORKDIR /app
# Once the repo made pubilc, this can become:
## go install github.com/FigureTechnologies/kong-jwt-wallet/cmd/jwt-wallet@latest
RUN go build -o jwt-wallet ./cmd/jwt-wallet

FROM kong:2.7.0-alpine
# Once the repo made public, this can become:
## COPY --from=build /go/bin/jwt-wallet /usr/local/bin/
COPY --from=build /app/jwt-wallet /usr/local/bin/
ADD config.yml /opt/
# Set the needed env vars to run the jwt-wallet plugin
ENV KONG_PLUGINSERVER_NAMES="jwt-wallet" \
	KONG_PLUGINSERVER_JWT_WALLET_START_CMD="/usr/local/bin/jwt-wallet" \
	KONG_PLUGINSERVER_JWT_WALLET_QUERY_CMD="/usr/local/bin/jwt-wallet -dump" \
	KONG_PLUGINS="bundled,jwt-wallet"

