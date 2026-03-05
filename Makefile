# OpenIDX Makefile
# Build, test, and deploy automation

.PHONY: all build test lint clean dev dev-infra docker helm docs

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.CommitHash=$(COMMIT_HASH)"

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build $(LDFLAGS)
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOLINT := golangci-lint

# Docker parameters
DOCKER := docker
DOCKER_COMPOSE := docker-compose
DOCKER_REGISTRY ?= ghcr.io/openidx

# Kubernetes parameters
KUBECTL := kubectl
HELM := helm
NAMESPACE ?= openidx

# Services
SERVICES := identity-service governance-service provisioning-service audit-service gateway-service admin-api oauth-service

#---------------------------------------------------------------------------
# Default target
#---------------------------------------------------------------------------

all: deps lint test build

#---------------------------------------------------------------------------
# Dependencies
#---------------------------------------------------------------------------

deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	cd web/admin-console && npm install

deps-tools:
	@echo "🔧 Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

#---------------------------------------------------------------------------
# Build
#---------------------------------------------------------------------------

build: build-services build-web

build-services:
	@echo "🔨 Building services..."
	@for service in $(SERVICES); do \
		echo "  Building $$service..."; \
		$(GOBUILD) -o bin/$$service ./cmd/$$service; \
	done

build-web:
	@echo "🌐 Building web applications..."
	cd web/admin-console && npm run build

build-linux:
	@echo "🐧 Building for Linux..."
	@for service in $(SERVICES); do \
		GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/linux/$$service ./cmd/$$service; \
	done

#---------------------------------------------------------------------------
# Testing
#---------------------------------------------------------------------------

test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race -cover ./...

test-coverage:
	@echo "📊 Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration:
	@echo "🔗 Running integration tests..."
	$(GOTEST) -v -tags=integration ./test/integration/...

test-e2e:
	@echo "🎭 Running end-to-end tests..."
	cd test/e2e && npm test

#---------------------------------------------------------------------------
# Linting
#---------------------------------------------------------------------------

lint:
	@echo "🔍 Running linters..."
	$(GOLINT) run ./...

lint-fix:
	@echo "🔧 Fixing lint issues..."
	$(GOLINT) run --fix ./...

lint-web:
	@echo "🔍 Linting web applications..."
	cd web/admin-console && npm run lint

#---------------------------------------------------------------------------
# Development
#---------------------------------------------------------------------------

dev-infra:
	@echo "🏗️  Starting infrastructure services..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.infra.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "✅ Infrastructure ready!"

dev:
	@echo "🚀 Starting development environment..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml up -d
	@echo "✅ Services running at:"
	@echo "   - Admin Console:  http://localhost:3000"
	@echo "   - APISIX Gateway: http://localhost:8088"
	@echo "   - OAuth Service:  http://localhost:8006"
	@echo "   - Identity API:   http://localhost:8001"
	@echo "   - Admin API:      http://localhost:8005"
	@echo "   - Mailpit UI:     http://localhost:8025"

dev-stop:
	@echo "🛑 Stopping development environment..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml down

dev-logs:
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml logs -f

dev-logs-service:
	@test -n "$(SVC)" || (echo "Usage: make dev-logs-service SVC=identity-service" && exit 1)
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml logs -f $(SVC)

dev-status:
	@echo "📊 Service status:"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml ps

dev-restart:
	@echo "🔄 Restarting development environment..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml restart

dev-clean:
	@echo "🧹 Cleaning development environment (removes volumes)..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml down -v --remove-orphans

#---------------------------------------------------------------------------
# Docker
#---------------------------------------------------------------------------

docker-build:
	@echo "🐳 Building Docker images..."
	@for service in $(SERVICES); do \
		echo "  Building $$service image..."; \
		$(DOCKER) build -t $(DOCKER_REGISTRY)/$$service:$(VERSION) \
			--build-arg VERSION=$(VERSION) \
			-f deployments/docker/Dockerfile.$$service .; \
	done
	$(DOCKER) build -t $(DOCKER_REGISTRY)/admin-console:$(VERSION) \
		--build-arg SRC_DIR=. \
		-f deployments/docker/Dockerfile.admin-console ./web/admin-console

docker-push:
	@echo "📤 Pushing Docker images..."
	@for service in $(SERVICES); do \
		$(DOCKER) push $(DOCKER_REGISTRY)/$$service:$(VERSION); \
	done
	$(DOCKER) push $(DOCKER_REGISTRY)/admin-console:$(VERSION)

#---------------------------------------------------------------------------
# Kubernetes & Helm
#---------------------------------------------------------------------------

helm-deps:
	@echo "📦 Updating Helm dependencies..."
	$(HELM) dependency update deployments/kubernetes/helm/openidx

helm-lint:
	@echo "🔍 Linting Helm chart..."
	$(HELM) lint deployments/kubernetes/helm/openidx

helm-template:
	@echo "📄 Rendering Helm templates..."
	$(HELM) template openidx deployments/kubernetes/helm/openidx \
		--namespace $(NAMESPACE) \
		--values deployments/kubernetes/helm/openidx/values.yaml

helm-install:
	@echo "🚀 Installing OpenIDX..."
	$(HELM) upgrade --install openidx deployments/kubernetes/helm/openidx \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--values deployments/kubernetes/helm/openidx/values.yaml \
		--wait

helm-uninstall:
	@echo "🗑️  Uninstalling OpenIDX..."
	$(HELM) uninstall openidx --namespace $(NAMESPACE)

k8s-apply:
	@echo "📦 Applying Kubernetes manifests..."
	$(KUBECTL) apply -k deployments/kubernetes/overlays/development

k8s-delete:
	@echo "🗑️  Deleting Kubernetes resources..."
	$(KUBECTL) delete -k deployments/kubernetes/overlays/development

#---------------------------------------------------------------------------
# Infrastructure
#---------------------------------------------------------------------------

tf-init:
	@echo "🏗️  Initializing Terraform..."
	cd deployments/terraform && terraform init

tf-plan:
	@echo "📋 Planning Terraform changes..."
	cd deployments/terraform && terraform plan -out=tfplan

tf-apply:
	@echo "🚀 Applying Terraform changes..."
	cd deployments/terraform && terraform apply tfplan

tf-destroy:
	@echo "💥 Destroying infrastructure..."
	cd deployments/terraform && terraform destroy

#---------------------------------------------------------------------------
# Code Generation
#---------------------------------------------------------------------------

generate:
	@echo "⚙️  Generating code..."
	$(GOCMD) generate ./...

swagger:
	@echo "📚 Generating Swagger documentation..."
	swag init -g cmd/admin-api/main.go -o api/swagger

proto:
	@echo "📝 Generating protobuf code..."
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

#---------------------------------------------------------------------------
# Documentation
#---------------------------------------------------------------------------

docs:
	@echo "📖 Building documentation..."
	cd docs && mkdocs build

docs-serve:
	@echo "📖 Serving documentation..."
	cd docs && mkdocs serve

#---------------------------------------------------------------------------
# Cleanup
#---------------------------------------------------------------------------

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	rm -rf coverage.out coverage.html
	rm -rf web/admin-console/build
	rm -rf web/admin-console/node_modules

clean-docker:
	@echo "🐳 Cleaning Docker resources..."
	$(DOCKER) system prune -f

#---------------------------------------------------------------------------
# Release
#---------------------------------------------------------------------------

release: lint test build docker-build docker-push
	@echo "🎉 Release $(VERSION) complete!"

#---------------------------------------------------------------------------
# Help
#---------------------------------------------------------------------------

help:
	@echo "OpenIDX Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  deps           Install dependencies"
	@echo "  build          Build all services and web apps"
	@echo "  test           Run unit tests"
	@echo "  lint           Run linters"
	@echo "  dev            Start development environment"
	@echo "  dev-stop       Stop development environment"
	@echo "  docker-build   Build Docker images"
	@echo "  docker-push    Push Docker images"
	@echo "  helm-install   Install via Helm"
	@echo "  clean          Clean build artifacts"
	@echo "  help           Show this help"
