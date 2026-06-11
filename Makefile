BONGSU_VERSION ?= 0.1.0
BONGSU_COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BONGSU_BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_BUILD_FLAGS ?= -trimpath
LDFLAGS := -s -w -X main.version=$(BONGSU_VERSION) -X main.commit=$(BONGSU_COMMIT) -X main.buildDate=$(BONGSU_BUILD_DATE)

.PHONY: build build-agent build-server tidy test test-integration test-all dev dev-up dev-down docker docker-agent docker-server package clean

build: build-server build-agent

build-server:
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o bin/bongsu-server ./cmd/server

build-agent:
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o bin/bongsu-agent ./cmd/agent

tidy:
	go mod tidy

test:
	go test ./...

# DB-backed integration suite; needs BONGSU_TEST_DB (a *_test database DSN)
# or a reachable bongsu-postgres dev container. Skips cleanly without one.
test-integration:
	./scripts/verify-integration-db.sh

test-all: test test-integration

dev: dev-up

dev-up:
	cd deploy && docker compose up -d --build

dev-down:
	cd deploy && docker compose down

docker: docker-server docker-agent

docker-server:
	docker build --build-arg BONGSU_VERSION=$(BONGSU_VERSION) -t bongsu-server:$(BONGSU_VERSION) -t bongsu-server:latest -f deploy/Dockerfile.server .

docker-agent:
	docker build --build-arg BONGSU_VERSION=$(BONGSU_VERSION) -t bongsu-agent:$(BONGSU_VERSION) -t bongsu-agent:latest -f deploy/Dockerfile.agent .

package:
	./scripts/package.sh $(BONGSU_VERSION)

clean:
	rm -rf bin/
	rm -f bongsu-*.tar.gz trivy-db.tar.gz
