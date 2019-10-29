.PHONY: build run

all: install

build:
	go build -v -o bin/security-labeller ./cmd/security-labeller

run: build
	./bin/security-labeller -kubeconfig ~/.kube/config  -config example-config.yaml

installcrds:
	kubectl create -f deploy/imagemanifestvuln.yaml

devenv: installcrds
	kubectl apply -f deploy/examples/

apis/secscan/v1alpha1/zz_generated.deepcopy.go: apis/secscan/v1alpha1/types.go $(CODEGEN_IMAGE)
	docker run --rm \
	-v $(PWD):$(DOCKER_REPO_ROOT) \
	-w $(DOCKER_REPO_ROOT) \
	$(IMAGE) \
	deepcopy-gen \
	-i github.com/coreos-inc/security-labeller/apis/secscan/v1alpha1 \
	-v=4 \
	--logtostderr \
	--output-file-base zz_generated.deepcopy
	go fmt apis/secscan/v1alpha1/zz_generated.deepcopy.go

apis/v1alpha1/openapi_generated.go: apis/v1alpha1/types.go $(CODEGEN_IMAGE)
	docker run --rm \
	-v $(PWD):$(DOCKER_REPO_ROOT) \
	-w $(DOCKER_REPO_ROOT) \
	$(IMAGE) \
	openapi-gen \
	-i github.com/coreos-inc/security-labeller/apis/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/api/core/v1 \
	-v=4 \
	-p github.com/coreos-inc/security-labeller/apis/v1alpha1
	go fmt apis/v1alpha1/openapi_generated.go

generated: apis/v1alpha1/zz_generated.deepcopy.go $(CODEGEN_IMAGE)
	docker run --rm \
	-v $(PWD):$(DOCKER_REPO_ROOT) \
	-w $(DOCKER_REPO_ROOT) \
	$(IMAGE) \
	"/go/src/k8s.io/code-generator/generate-groups.sh"  \
	"all" \
	"github.com/coreos-inc/security-labeller/generated" \
	"github.com/coreos-inc/security-labeller/apis" \
	"v1alpha1" \
	$@


# =====================
# Code generators image
# =====================
KUBERNETES_VERSION = 1.15
DOCKER_REPO_ROOT = /go/src/github.com/coreos-inc/security-labeller
IMAGE = codegen:$(KUBERNETES_VERSION)

# code-generator container for generate-groups.sh
# https://github.com/kubernetes/code-generator
CODEGEN_IMAGE:
	docker build -f Dockerfile.codegen -t $(IMAGE) .
