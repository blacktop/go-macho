REPO=blacktop
NAME=go-macho
NEXT_VERSION:=$(shell svu patch)

.PHONY: dev-deps
dev-deps: ## Install the dev dependencies
	@brew install gh
	@go install github.com/caarlos0/svu@v1.4.1

OBJC_SRC := internal/testdata/test.m
OBJC_BIN := internal/testdata/objc_fixture
CLANG    := $(shell xcrun -f clang 2>/dev/null)
SDK      := $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)

.PHONY: objc-fixture
objc-fixture: ## Build the ObjC demo binary with protocol class properties (requires Xcode CLT)
	@if [ "$(CLANG)" = "" ]; then echo "xcrun clang not found; install Xcode Command Line Tools"; exit 1; fi
	@echo "Compiling $(OBJC_SRC) -> $(OBJC_BIN)"
	@$(CLANG) -fobjc-arc -isysroot "$(SDK)" -framework Foundation -o "$(OBJC_BIN)" "$(OBJC_SRC)"
	@echo "Built $(OBJC_BIN)"

.PHONY: bump
bump: ## Tag and push the next patch version
	@echo " > Tagging ${NEXT_VERSION}"
	@git tag -a ${NEXT_VERSION} -m "Release ${NEXT_VERSION}"
	@git push origin ${NEXT_VERSION}

.PHONY: fmt
fmt: ## Format code
	@echo " > Formatting code"
	@gofmt -w -r 'interface{} -> any' .
	@goimports -w .
	@gofmt -w -s .
	@go mod tidy	

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help