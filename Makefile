GOPKG = github.com/quay/container-security-operator

.PHONY: all
all: install

.PHONY: build
build:
	go build -v -o bin/security-labeller ./cmd/security-labeller

.PHONY: run
run: build
	./bin/security-labeller -kubeconfig ~/.kube/config  -config example/example-config.yaml

.PHONY: installcrds
installcrds:
	kubectl create -f deploy/imagemanifestvuln.yaml

.PHONY: devenv
devenv: installcrds
	kubectl apply -f deploy/examples/

.PHONY: vendor
vendor:
	go mod vendor

.PHONY: deepcopy
deepcopy:
	deepcopy-gen \
	-i github.com/quay/container-security-operator/apis/secscan/v1alpha1 \
	-v=4 \
	--logtostderr \
	--output-file-base zz_generated.deepcopy
	go fmt apis/secscan/v1alpha1/zz_generated.deepcopy.go

.PHONY: openapi
openapi:
	openapi-gen \
	-i github.com/quay/container-security-operator/apis/secscan/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/api/core/v1 \
	-v=4 \
	-p github.com/quay/container-security-operator/apis/secscan/v1alpha1
	go fmt apis/secscan/v1alpha1/openapi_generated.go

.PHONY: clientset
clientset:
	client-gen \
	-v=4 \
	--input-base     "" \
	--clientset-name "versioned" \
	--input	         "$(GOPKG)/apis/secscan/v1alpha1" \
	--output-package "$(GOPKG)/generated"

.PHONY: listers
listers:
	lister-gen \
	-v=4 \
	--input-dirs     "$(GOPKG)/apis/secscan/v1alpha1" \
	--output-package "$(GOPKG)/generated/listers"

.PHONY: informers
informers:
	informer-gen \
	-v=4 \
	--versioned-clientset-package "$(GOPKG)/generated/versioned" \
	--listers-package "$(GOPKG)/generated/listers" \
	--input-dirs      "$(GOPKG)/apis/secscan/v1alpha1" \
	--output-package  "$(GOPKG)/generated/informers"

.PHONY: codegen
codegen: deepcopy \
	clientset \
	listers \
	informers \
	openapi

.PHONY: codegen-container
codegen-container: BUILD_CODEGEN_IMAGE
	docker run --rm --name codegen \
	-v $(PWD):$(REPO_ROOT) \
	-w $(REPO_ROOT) \
	$(CODEGEN_IMAGE) \
	make codegen


# =====================
# Code generators image
# =====================
REPO_ROOT = /go/src/$(GOPKG)
CODEGEN_IMAGE = container-security-operator:codegen

# https://github.com/kubernetes/code-generator
.PHONY: BUILD_CODEGEN_IMAGE
BUILD_CODEGEN_IMAGE:
	docker build -f Dockerfile.codegen -t $(CODEGEN_IMAGE) .
