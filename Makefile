# xdr-agent - Modular XDR endpoint security agent for Linux
# Copyright (C) 2026  Diego A. Guillen-Rosaperez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
	KEEP_STAGING=$(KEEP_STAGING) bash ./packaging/deb/build.sh $(VERSION) amd64

rpm:
	bash ./packaging/rpm/build.sh $(VERSION) amd64

packages:
	bash ./packaging/build_multi_arch.sh $(VERSION)

clean:
	rm -rf dist
