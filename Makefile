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
	kubectl create -f deploy/imagemanifestvuln.crd.yaml

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


# =======================
# CSV Manifest generation
# =======================
MANIFESTGEN_IMAGE = container-security-operator:manifestgen

MANIFESTGEN_WORKDIR ?= scripts
MANIFESTGEN_OUTPUT_DIR ?= deploy
MANIFESTGEN_VERSION ?= master
MANIFESTGEN_OPT_FLAGS ?= --upstream --skip-pull --yaml

OPERATOR_IMAGE ?= quay.io/quay/container-security-operator
OPERATOR_IMAGE_REF ?= $(shell \
	docker pull $(OPERATOR_IMAGE):$(MANIFESTGEN_VERSION) > /dev/null && \
	docker inspect $(OPERATOR_IMAGE):$(MANIFESTGEN_VERSION) | jq '.[0].RepoDigests[] | select(. | startswith("$(OPERATOR_IMAGE)"))' \
)

.PHONY: BUILD_MANIFESTGEN_IMAGE
BUILD_MANIFEST_GEN_IMAGE:
	docker build -t $(MANIFESTGEN_IMAGE) scripts

.PHONY: manifestgen-container
manifestgen-container: BUILD_MANIFEST_GEN_IMAGE
	docker run --rm --name manifestgen \
	-v $(PWD)/$(MANIFESTGEN_WORKDIR):/workspace/$(MANIFESTGEN_WORKDIR) \
	-v $(PWD)/$(MANIFESTGEN_OUTPUT_DIR):/workspace/$(MANIFESTGEN_OUTPUT_DIR) \
	$(MANIFESTGEN_IMAGE) \
	python $(MANIFESTGEN_WORKDIR)/generate_csv.py $(MANIFESTGEN_VERSION) $(MANIFESTGEN_PREVIOUS_VERSION) \
	--workdir $(MANIFESTGEN_WORKDIR) --output-dir $(MANIFESTGEN_OUTPUT_DIR) \
	--image $(OPERATOR_IMAGE_REF)	$(MANIFESTGEN_OPT_FLAGS)

# Example:
# $ OPERATOR_IMAGE_REF=quay.io/quay/container-security-operator:v1.0.0 MANIFESTGEN_OUTPUT_DIR=testingscript MANIFESTGEN_VERSION=v3.3.0 make manifestgen-container
