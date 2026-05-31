BONGSU_VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(BONGSU_VERSION)

.PHONY: build build-agent build-server tidy dev dev-up dev-down docker docker-agent docker-server package clean

build: build-server build-agent

build-server:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/bongsu-server ./cmd/server

build-agent:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/bongsu-agent ./cmd/agent

tidy:
	go mod tidy

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
