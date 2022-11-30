
# Image URL to use all building/pushing image targets
IMG_REPOSITORY ?= quay.io/akrejcir/vm-console-access
IMG_TAG ?= latest
IMG ?= ${IMG_REPOSITORY}:${IMG_TAG}

.PHONY:build
build:
	go build -o bin/console main.go

.PHONY: build-container
build-container:
	podman build -t ${IMG} .

.PHONY: push-container
push-container:
	podman push ${IMG}

.PHONY: deploy
deploy:
	echo "Not implemented"

.PHONY: undeploy
undeploy:
	echo "Not implemented"

.PHONY: generate
generate:
	echo "Not implemented"

.PHONY: test
test:
	echo "Not implemented"
