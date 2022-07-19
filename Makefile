GOPKG = github.com/quay/container-security-operator
GENDIR = /tmp/code-generator

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
	kubectl create -f bundle/imagemanifestvuln.crd.yaml

.PHONY: get-code-generator
get-code-generator:
	rm -rf $(GENDIR) || true
	git clone --depth=1 \
		--branch v0.24.0 \
		https://github.com/kubernetes/code-generator.git \
		$(GENDIR)

.PHONY: devenv
devenv: installcrds
	kubectl apply -f bundle/examples/

.PHONY: vendor
vendor:
	go mod vendor

.PHONY: codegen
codegen:
	$(GENDIR)/generate-groups.sh all \
		$(GOPKG)/generated \
		$(GOPKG) \
		apis/secscan:v1alpha1\
		--go-header-file=$(GENDIR)/hack/boilerplate.go.txt \
		--output-base=/tmp
	mv /tmp/$(GOPKG)/apis/secscan/v1alpha1/zz_generated.deepcopy.go apis/secscan/v1alpha1/
	rm -rf generated
	mv /tmp/$(GOPKG)/generated .

