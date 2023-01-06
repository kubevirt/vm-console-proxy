
# Image URL to use all building/pushing image targets
IMG_REPOSITORY ?= quay.io/akrejcir/vm-console-proxy
IMG_TAG ?= latest
IMG ?= ${IMG_REPOSITORY}:${IMG_TAG}

SRC_PATHS_TESTS = ./pkg/...

.PHONY:build
build: fmt vet
	go build -o bin/console main.go

.PHONY: build-container
build-container: fmt vet test
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
	go test -v $(SRC_PATHS_TESTS)

.PHONY: functest
functest:
	go test -v -timeout 0 -count 1 ./tests/...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...