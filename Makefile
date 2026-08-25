.RECIPEPREFIX := >
TARGETS := $(shell ls scripts)

DAPPER_IMAGE ?= pasturestack-network-plugin-manager-dapper:go1.27.0
DAPPER_HOST_ARCH ?= amd64
DAPPER_SOURCE ?= /go/src/github.com/PastureStack/network-plugin-manager

.dapper:
>docker build \
>  --pull \
>  --network "$${DOCKER_BUILD_NETWORK:-host}" \
>  --build-arg DAPPER_HOST_ARCH=$(DAPPER_HOST_ARCH) \
>  -t $(DAPPER_IMAGE) \
>  -f Dockerfile.dapper .

$(TARGETS): .dapper
>docker run --rm \
>  -v $(CURDIR):$(DAPPER_SOURCE) \
>  -v /var/run/docker.sock:/var/run/docker.sock \
>  -e DAPPER_UID=$$(id -u) \
>  -e DAPPER_GID=$$(id -g) \
>  -e ARCH=$(DAPPER_HOST_ARCH) \
>  -e TAG \
>  -e REPO \
>  -e IMAGE_NAMESPACE \
>  -e DOCKER_BUILD_NETWORK \
>  -e VERSION_OVERRIDE \
>  $(DAPPER_IMAGE) $@

trash: deps

trash-keep: deps

deps: .dapper
>docker run --rm \
>  -v $(CURDIR):$(DAPPER_SOURCE) \
>  -e DAPPER_UID=$$(id -u) \
>  -e DAPPER_GID=$$(id -g) \
>  -e ARCH=$(DAPPER_HOST_ARCH) \
>  -e DOCKER_BUILD_NETWORK \
>  -e VERSION_OVERRIDE \
>  $(DAPPER_IMAGE) /bin/bash -lc 'echo "vendor directory is committed; no dependency bootstrap required"'

.DEFAULT_GOAL := ci

.PHONY: .dapper $(TARGETS) trash trash-keep deps
