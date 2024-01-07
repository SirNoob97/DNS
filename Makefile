SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:

ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >

PREFIX=$${PREFIX:=$$GOBIN}

COMPILER=go
COMPILE_OPTS=build -o
COMPILE=$(COMPILER) $(COMPILE_OPTS)
BUILD_DIR=bin

all: build

$(BUILD_DIR)/dns: clean-$(BUILD_DIR)
> @mkdir -p $(@D)
> @$(COMPILE) $@

build: $(BUILD_DIR)/dns

clean-$(BUILD_DIR):
> @rm -rf $(BUILD_DIR)

clean: clean-$(BUILD_DIR)

test: clean
> @go test -race ./...

install:
> @[ -x $(BUILD_DIR)/dns ] || $(MAKE) build
> @echo $(PREFIX) > testing
> @mv $(BUILD_DIR)/dns $(PREFIX)
> @$(MAKE) clean

.PHONY: build install test clean
