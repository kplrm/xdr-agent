VERSION ?= $(shell cat VERSION)

.PHONY: build run enroll deb rpm packages clean

build:
	go build -trimpath -ldflags "-s -w -X xdr-agent/internal/buildinfo.Version=$(VERSION)" -o dist/xdr-agent ./cmd/xdr-agent

run: build
	./dist/xdr-agent run --config ./config/config.json

enroll: build
	./dist/xdr-agent enroll --config ./config/config.json

deb:
	bash ./packaging/deb/build.sh $(VERSION) amd64

rpm:
	bash ./packaging/rpm/build.sh $(VERSION) amd64

packages:
	bash ./packaging/build_multi_arch.sh $(VERSION)

clean:
	rm -rf dist
