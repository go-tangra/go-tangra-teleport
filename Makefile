GO        ?= go
PKGS      := $(shell $(GO) list ./... | grep -v /ui/)
COVER_OUT := coverage.out

.PHONY: lint license spike vuln test test-integration cover fuzz generate ui-build e2e build build-ui image redaction-scan compose-up compose-down

lint: license
	$(GO) vet ./...
	staticcheck ./...
	gosec -quiet -exclude-generated -exclude-dir=ui ./...

# Principle VI: no AGPL module (github.com/gravitational/teleport/lib and
# friends) may enter the module graph; only the Apache-2.0 api module is used.
license:
	./scripts/license-check.sh

vuln:
	./scripts/vulncheck.sh

test:
	$(GO) test -race -count=1 ./...

# Testcontainers suites (TimescaleDB, Valkey, Teleport CE); they skip cleanly
# when Docker is unavailable.
test-integration:
	$(GO) test -race -count=1 -tags integration ./internal/repodb/ ./tests/integration/...

# Live-cluster spikes (research D1/D2); need TELEPORT_SPIKE_PROXY and
# TELEPORT_SPIKE_IDENTITY (a path to an identity file).
spike:
	$(GO) test -count=1 -tags spike -run Spike -v ./internal/teleportapi/

# Generated protobuf, SQL bindings (internal/store, internal/repodb), wiring
# (internal/app, cmd) and test packages are exercised by the tagged integration
# suite and are excluded from the unit gate on purpose.
COVERPKG := $(shell $(GO) list ./... | grep -v -E '/api/|/internal/store$$|/internal/repodb$$|/internal/app$$|/valkeykv$$|/cmd/|/tests/|/ui|/internal/stream$$|/repotest' | paste -sd, -)

cover:
	$(GO) test -count=1 -coverprofile=$(COVER_OUT) -coverpkg=$(COVERPKG) $(PKGS)
	./scripts/coverage-gate.sh $(COVER_OUT)

# Every parser has a fuzz target; each runs for FUZZTIME (default 30 s).
FUZZTIME ?= 30s
fuzz:
	@for f in $$($(GO) test -list 'Fuzz.*' ./tests/fuzz/ | grep '^Fuzz'); do \
		echo "fuzz: $$f"; $(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) ./tests/fuzz/ || exit 1; done

generate:
	buf generate

# SR-002/SC-007: sentinel credentials never appear in captured output.
redaction-scan:
	./scripts/redaction-scan.sh

# Build the federated UI remote (produces ui/dist consumed by the -tags ui build).
ui-build:
	cd ui && npm ci && npm run build

# Browser end-to-end suite (Playwright) against a running dev stack.
e2e:
	cd ui && npx playwright test

# Build the service binary without the embedded UI.
build:
	$(GO) build -o bin/teleportsvc ./cmd/teleportsvc

# Build the service binary with the embedded UI remote (requires ui-build first).
build-ui: ui-build
	$(GO) build -tags "ui" -o bin/teleportsvc ./cmd/teleportsvc

# Build the container image; NODE_AUTH_TOKEN (read:packages) installs @go-tangra/ui.
image:
	DOCKER_BUILDKIT=1 docker buildx build --secret id=npm_token,env=NODE_AUTH_TOKEN -t go-tangra-teleport:dev .

# Development stack: the core freya-stack (go-tangra/deploy/stack, checked out
# next to this repository) plus deploy/compose.dev.yaml (the teleport
# database, Valkey user, gateway allow-list entry, join token and service).
# PROFILES=teleport-ce also starts a Teleport CE test cluster.
CORE_STACK ?= ../go-tangra/deploy/stack
COMPOSE_DEV = TELEPORT_REPO=$(CURDIR) docker compose -p freya-stack --project-directory $(CORE_STACK) \
	-f $(CORE_STACK)/compose.yaml -f $(CURDIR)/deploy/compose.dev.yaml $(foreach p,$(PROFILES),--profile $(p))

compose-up:
	$(COMPOSE_DEV) up -d teleport $(if $(filter teleport-ce,$(PROFILES)),teleport-ce)

# Stops and removes only the module's containers and volumes; the core stack
# keeps running.
compose-down:
	$(COMPOSE_DEV) rm -sfv teleport teleport-token teleport-gateway-allow teleport-valkey-user teleport-db-init teleport-ce
	-docker volume rm freya-stack_teleport-state freya-stack_teleport-ce-data
