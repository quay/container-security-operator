#!/usr/bin/env bash
# builds the operator and its OLM catalog index and pushes it to quay.io.
#
# by default, the built catalog index is tagged with
# `quay.io/projectquay/container-security-operator-index:1.0.6-unstable`. you can override the
# tag alone by exporting TAG before executing this script.
#
# To push to your own registry, override the REGISTRY and NAMESPACE env vars,
# i.e:
#   $ REGISTRY=quay.io NAMESPACE=yourusername ./hack/build.sh
#
# REQUIREMENTS:
#  * a valid login session to a container registry.
#  * `docker`
#  * `yq`
#  * `opm`
#
# NOTE: this script will modify the following files:
#  - bundle/manifests/container-security-operator.clusterserviceversion.yaml
#  - bundle/metadata/annotations.yaml
# if `git` is available it will be used to checkout changes to the above files.
# this means that if you made any changes to them and want them to be persisted,
# make sure to commit them before running this script.
set -e

export OPERATOR_NAME='container-security-operator-test'
export REGISTRY=${REGISTRY:-'quay.io'}
export NAMESPACE=${NAMESPACE:-'projectquay'}
export TAG=${TAG:-'v1.0.6'}
export CSV_PATH=${CSV_PATH:-'bundle/manifests/container-security-operator.clusterserviceversion.yaml'}
export ANNOTATIONS_PATH=${ANNOTATIONS_PATH:-'bundle/metadata/annotations.yaml'}

function cleanup {
	# shellcheck disable=SC2046
	if [ -x $(command -v git >/dev/null 2>&1) ]; then
		git checkout "${CSV_PATH}" >/dev/null 2>&1
		git checkout "${ANNOTATIONS_PATH}" >/dev/null 2>&1
	fi
}

trap cleanup EXIT

# prints pre-formatted info output.
function info {
	echo "INFO $(date '+%Y-%m-%dT%H:%M:%S') $*"
}

# prints pre-formatted error output.
function error {
	>&2 echo "ERROR $(date '+%Y-%m-%dT%H:%M:%S') $*"
}

function digest() {
	declare -n ret=$2
	IMAGE=$1
        echo $IMAGE
	docker pull "${IMAGE}"
	# shellcheck disable=SC2034
	ret=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}")
}

docker buildx build --push --platform="linux/amd64,linux/s390x,linux/ppc64le" -t "${REGISTRY}/${NAMESPACE}/container-security-operator:${TAG}" .
digest "${REGISTRY}/${NAMESPACE}/container-security-operator:${TAG}" OPERATOR_DIGEST

# need exporting so that yq can see them
export OPERATOR_DIGEST

# prepare operator files, then build and push operator bundle and catalog
# index images.

yq eval -i '
	.metadata.name = strenv(OPERATOR_NAME) |
	.metadata.annotations.version = strenv(TAG) |
	.metadata.annotations.containerImage = strenv(OPERATOR_DIGEST) |
	del(.spec.replaces) |
	.spec.install.spec.deployments[0].name = strenv(OPERATOR_NAME) |
	.spec.install.spec.deployments[0].spec.template.spec.containers[0].image = strenv(OPERATOR_DIGEST)
	' "${CSV_PATH}"

yq eval -i '
	.annotations."operators.operatorframework.io.bundle.channel.default.v1" = "test" |
	.annotations."operators.operatorframework.io.bundle.channels.v1" = "test"
	' "${ANNOTATIONS_PATH}"

docker buildx build --push -f ./bundle/Dockerfile --platform="linux/amd64,linux/s390x,linux/ppc64le" -t "${REGISTRY}/${NAMESPACE}/container-security-operator-bundle:${TAG}" ./bundle
digest "${REGISTRY}/${NAMESPACE}/container-security-operator-bundle:${TAG}" BUNDLE_DIGEST

AMD64_DIGEST=$(skopeo inspect --raw docker://${REGISTRY}/${NAMESPACE}/container-security-operator-bundle:${TAG} | \
	jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux").digest')
POWER_DIGEST=$(skopeo inspect --raw  docker://${REGISTRY}/${NAMESPACE}/container-security-operator-bundle:${TAG} | \
	jq -r '.manifests[] | select(.platform.architecture == "ppc64le" and .platform.os == "linux").digest')
Z_DIGEST=$(skopeo inspect --raw  docker://${REGISTRY}/${NAMESPACE}/container-security-operator-bundle:${TAG} | \
	jq -r '.manifests[] | select(.platform.architecture == "s390x" and .platform.os == "linux").digest')

opm index add --build-tool docker --bundles "${REGISTRY}/${NAMESPACE}/container-security-operator-bundle@${AMD64_DIGEST}" \
       	-t "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-amd64"
docker push "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-amd64"
opm index add --build-tool docker --bundles "${REGISTRY}/${NAMESPACE}/container-security-operator-bundle@${Z_DIGEST}" \
       	-t "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-s390x"
docker push "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-s390x"
opm index add --build-tool docker --bundles "${REGISTRY}/${NAMESPACE}/container-security-operator-bundle@${POWER_DIGEST}" \
	-t "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-ppc64le"
docker push "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-ppc64le"
docker manifest create --amend "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}" \
	"${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-amd64" \
	"${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-s390x" \
	"${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}-ppc64le"
docker manifest push "${REGISTRY}/${NAMESPACE}/container-security-operator-index:${TAG}"
