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

.PHONY: build rules rules-test api-test run enroll deb rpm packages clean test prevention-test vet

# Generate Linux rules, check the API contract, and compile dist/xdr-agent.
build: rules api-test
	@if [ -z "$(GO)" ]; then echo "Go toolchain not found. Install Go or add it to PATH."; exit 127; fi
	$(GO) build -trimpath -ldflags "-s -w -X xdr-agent/internal/buildinfo.Version=$(VERSION)" -o dist/xdr-agent ./cmd/xdr-agent

# Build and run the agent in the foreground with the repository config.
run: build
	./dist/xdr-agent run --config ./config/config.json

# Build and enroll the installed service from the repository config.
enroll: build
	@if [ -z "$(ENROLLMENT_TOKEN)" ]; then echo "Set ENROLLMENT_TOKEN, e.g. make enroll ENROLLMENT_TOKEN=..."; exit 2; fi
	@sudo ./dist/xdr-agent enroll "$(ENROLLMENT_TOKEN)" --config ./config/config.json

# Build an amd64 Debian package with the agent and systemd unit.
deb:
	KEEP_STAGING=$(KEEP_STAGING) bash ./packaging/deb/build.sh $(VERSION) amd64

# Build an amd64 RPM package with the agent and systemd unit.
rpm:
	bash ./packaging/rpm/build.sh $(VERSION) amd64

# Build Debian and RPM packages for amd64 and arm64 by default.
packages:
	bash ./packaging/build_multi_arch.sh $(VERSION)

# Run contracts, unit checks, bounded enrollment, and real fanotify tests in Docker.
test: rules rules-test api-test
	$(GO) test ./... -count=1
	GO="$(GO)" python3 test/post_enroll_smoke.py
	$(MAKE) prevention-test

# Exercise real fanotify decisions only inside a disposable, bounded container.
prevention-test:
	GO="$(GO)" bash test/prevention_container.sh

# Run Go static analysis across all packages.
vet:
	$(GO) vet ./...

# Remove generated binaries and packages from dist/.
clean:
	rm -rf dist

# Every package regenerates the platform bundle from the supplied local snapshot.
YARA_SOURCE ?= yara-forge-core/yara-rules-core.yar

# bundle_yara.py filters Linux rules, and writes internal/detection/malware/bundle/{linux.yar,catalog.json}
rules:
	python3 tools/bundle_yara.py --source "$(YARA_SOURCE)" --platform linux

# Test the Python Linux-rule bundling logic.
rules-test:
	python3 -m unittest discover -s tools -p 'test_bundle_yara.py'

# Test Agent HTTP clients and Coordinator route compatibility.
api-test:
	GO="$(GO)" bash test/api_contract.sh
