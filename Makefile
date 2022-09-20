BUILDDIR ?= $(CURDIR)/build

ifeq (,$(VERSION))
  VERSION := $(shell git describe --exact-match 2>/dev/null)
  # if VERSION is empty, then populate it with branch's name and raw commit hash
  ifeq (,$(VERSION))
    VERSION := $(BRANCH_PRETTY)-$(COMMIT)
  endif
endif

UNAME_S = $(shell uname -s | tr '[A-Z]' '[a-z]')
UNAME_M = $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
	ARCH=amd64
endif

RELEASE_ZIP_BASE=figtech-$(UNAME_S)-$(ARCH)
RELEASE_ZIP_NAME=$(RELEASE_ZIP_BASE)-$(VERSION).zip
RELEASE_ZIP=$(BUILDDIR)/$(RELEASE_ZIP_NAME)

all: bin

.PHONY: bin
bin:
	go build -o jwt-wallet ./cmd/jwt-wallet

.PHONY: release
release:
	go build -o ${BUILDDIR}/jwt-wallet ./cmd/jwt-wallet

linux-release:
	$(MAKE) release
	cd $(BUILDDIR) && \
	  zip $(RELEASE_ZIP_NAME) jwt-wallet && \
	cd ..


.PHONY: lint
lint:
	find . -name '*.go' -type f -not -path "./vendor*" -not -path "*.git*" -not -path "*.pb.go" | xargs gofmt -w -d -s
	find . -name '*.go' -type f -not -path "./vendor*" -not -path "*.git*" -not -path "*.pb.go" -not -path "*/statik*" | xargs goimports -w -local github.com/FigureTechnologies/kong-jwt-wallet

.PHONY: http
http:
	python3 -m http.server 8888 --directory http/

.PHONY: docker
docker:
	docker build -t kong-test .

.PHONY: docker-run
docker-run:
	docker run -it --name kong-test --rm \
		-v $(CURDIR)/config.yml:/opt/config.yml \
		-e "KONG_DATABASE=off" \
		-e "KONG_LOG_LEVEL=debug" \
		-e "KONG_PROXY_LISTEN=0.0.0.0:8000" \
		-e "KONG_DECLARATIVE_CONFIG=/opt/config.yml" \
		-p 9000:8000 \
		kong-test:latest

.PHONY: docker-bash
docker-bash:
	docker run -it --name kong-test --rm \
		-e "KONG_DATABASE=off" \
		-e "KONG_LOG_LEVEL=debug" \
		-e "KONG_PROXY_LISTEN=0.0.0.0:8000" \
		-e "KONG_DECLARATIVE_CONFIG=/opt/config.yml" \
		-p 9000:8000 \
		kong-test:latest bash

.PHONY: curl
curl:
	# We only care about headers getting created
	curl -q -sSL -v -Hauthorization:$(shell cat ./token) localhost:8000/ >/dev/null

.PHONY: token
token:
	go run ./cmd/token/main.go

.PHONY: clean
clean:
	rm -f *.so jwt_wallet main main.so
