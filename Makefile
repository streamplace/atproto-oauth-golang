SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all executables
	go build -o oauth .

.PHONY: all
all: build

.PHONY: test
test: ## Run tests
	go clean -testcache && go test -v ./...

.PHONY: lint
lint: ## Verify code style and run static checks
	go vet ./...
	test -z $(gofmt -l ./...)

.PHONY: fmt
fmt: ## Run syntax re-formatting (modify in place)
	go fmt ./...

.PHONY: check
check: ## Compile everything, checking syntax (does not output binaries)
	go build ./...

.PHONY: test-server
test-server: ## Run the test server
	go run ./cmd/client_test

.PHONY: test-jwks
test-jwks: ## Create a test jwks file
	go run ./cmd/cmd generate-jwks --prefix demo

.PHONY: jwks
jwks:
	go run ./cmd/cmd generate-jwks

.env:
	if [ ! -f ".env" ]; then cp example.dev.env .env; fi
