
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

.PHONY: manifests
manifests:
	cd manifests && IMG_REPOSITORY=${IMG_REPOSITORY} IMG_TAG=${IMG_TAG} envsubst < kustomization.yaml.in > kustomization.yaml

.PHONY: deploy
deploy: manifests
	oc apply -k manifests

.PHONY: undeploy
undeploy: manifests
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

.PHONY: example-client
example-client:
	test -s "example-client/noVNC-1.3.0" || curl -L https://github.com/novnc/noVNC/archive/refs/tags/v1.3.0.tar.gz | tar -xz -C "example-client"

.PHONY: serve-client
serve-client: example-client
	cd "example-client" && python3 -m http.server
