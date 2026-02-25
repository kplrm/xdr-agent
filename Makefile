VERSION ?= $(shell cat VERSION)
GO ?= $(shell command -v go 2>/dev/null)

ifeq ($(GO),)
ifneq ("$(wildcard $(HOME)/.local/go/bin/go)","")
GO := $(HOME)/.local/go/bin/go
endif
endif

ifeq ($(GO),)
ifneq ("$(wildcard /usr/local/go/bin/go)","")
GO := /usr/local/go/bin/go
endif
endif

.PHONY: build run enroll deb rpm packages clean

build:
	@if [ -z "$(GO)" ]; then echo "Go toolchain not found. Install Go or add it to PATH."; exit 127; fi
	$(GO) build -trimpath -ldflags "-s -w -X xdr-agent/internal/buildinfo.Version=$(VERSION)" -o dist/xdr-agent ./cmd/xdr-agent

run: build
	./dist/xdr-agent run --config ./config/config.json

enroll: build
	@if [ -z "$(ENROLLMENT_TOKEN)" ]; then echo "Set ENROLLMENT_TOKEN, e.g. make enroll ENROLLMENT_TOKEN=..."; exit 2; fi
	./dist/xdr-agent enroll $(ENROLLMENT_TOKEN) --config ./config/config.json

deb:
	bash ./packaging/deb/build.sh $(VERSION) amd64

rpm:
	bash ./packaging/rpm/build.sh $(VERSION) amd64

packages:
	bash ./packaging/build_multi_arch.sh $(VERSION)

clean:
	rm -rf dist
