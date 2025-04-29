
# Image URL to use all building/pushing image targets
IMG_REPOSITORY ?= quay.io/kubevirt/vm-console-proxy
IMG_TAG ?= latest
IMG ?= ${IMG_REPOSITORY}:${IMG_TAG}

SRC_PATHS_TESTS = ./pkg/...
PROJECT_NAME = vm-console-proxy
MANIFETS_PATH = ./manifests

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

KUSTOMIZE ?= $(LOCALBIN)/kustomize
KUSTOMIZE_VERSION ?= v4.5.7
KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"

OPENAPI_GEN ?= $(LOCALBIN)/openapi-gen
OPENAPI_VERSION ?= c8a335a

KUBECONFIG ?= ~/.kube/config

.PHONY:build
build: fmt vet
	go build -o bin/console main.go

.PHONY: build-container
build-container: generate fmt vet test
	podman build -t ${IMG} .

.PHONY: push-container
push-container:
	podman push ${IMG}

.PHONY: manifests
manifests:
	cd manifests && IMG_REPOSITORY=${IMG_REPOSITORY} IMG_TAG=${IMG_TAG} envsubst < kustomization.yaml.in > kustomization.yaml

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	test -s $(LOCALBIN)/kustomize || curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN)

.PHONY: openapi-gen
openapi-gen: $(OPENAPI_GEN) ## Download openapi-gen locally if necessary.
$(OPENAPI_GEN): $(LOCALBIN)
	test -s $(OPENAPI_GEN) || GOBIN=$(LOCALBIN) go install k8s.io/kube-openapi/cmd/openapi-gen@$(OPENAPI_VERSION)

.PHONY: generate
generate: openapi-gen
	cd api && $(OPENAPI_GEN) \
	  --output-file zz_generated.openapi.go \
	  --output-dir ../pkg/generated/api/v1alpha1 \
	  --output-pkg github.com/kubevirt/vm-console-proxy/api/v1alpha1 \
	  --report-filename /dev/null \
	  k8s.io/apimachinery/pkg/apis/meta/v1 \
	  github.com/kubevirt/vm-console-proxy/api/v1alpha1

.PHONY: release-manifests
release-manifests: kustomize manifests
	mkdir -p ./_out
	$(KUSTOMIZE) build ${MANIFETS_PATH} > ./_out/${PROJECT_NAME}.yaml

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
	KUBECONFIG=$(KUBECONFIG) go test -v -timeout 0 -count 1 ./tests/...

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
