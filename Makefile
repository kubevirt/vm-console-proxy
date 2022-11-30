
# Image URL to use all building/pushing image targets
IMG_REPOSITORY ?= quay.io/akrejcir/vm-console-proxy
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
	oc apply -k manifests

.PHONY: undeploy
undeploy:
	oc delete -k manifests

.PHONY: test
test:
	echo "Not implemented"
