import argparse
import base64
import logging
import json
import os
import re
import subprocess
import sys
import yaml

from datetime import datetime
from urllib.parse import urljoin

from jinja2 import FileSystemLoader, Environment, StrictUndefined


logger = logging.getLogger(__name__)

LOGO_DOWNSTREAM_FILE = "img/downstream_logo.png"
LOGO_UPSTREAM_FILE = "img/upstream_logo.png"

PACKAGE_NAME = "container-security-operator"

# Default location for the image
REGISTRY_HOST = "quay.io"
REGISTRY_API_BASE = REGISTRY_HOST + "/api/v1/"

CSO_REPO = "projectquay/" + PACKAGE_NAME
CSO_IMAGE = REGISTRY_HOST + "/" + CSO_REPO
CSO_IMAGE_TAG = "master"

CSO_CATALOG_REPO = "projectquay/cso-catalog"
CSO_CATALOG_IMAGE = REGISTRY_HOST + "/" + CSO_CATALOG_REPO
CSO_CATALOG_IMAGE_TAG = "master"

# Default template values
K8S_API_VERSION = "v1alpha1"

# Jinja templates
TEMPLATE_DIR = "templates"
CSV_TEMPLATE_FILE = PACKAGE_NAME + ".clusterserviceversion.yaml.jnj"
CRD_TEMPLATE_FILES = [
    "imagemanifestvulns.secscan.quay.redhat.com.crd.yaml.jnj"
]

# Output
OUTPUT_MANIFEST_DIR = os.path.join("manifests", PACKAGE_NAME)
OUTPUT_CATALOG_FILE = "cso.catalogsource.yaml"

MANIFEST_DIGEST_REGEX = re.compile(r"sha256:[a-z0-9]{64}")
ARGUMENT_REGEX = re.compile(r"(-[\w])|(--[\w]+)")
VERSION_REGEX = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$")
MASTER_VERSION_REGEX = re.compile(r"^master$")


def normalize_version(version):
    if VERSION_REGEX.match(version):
        return version[1:]
    return version


def get_current_datetime():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_image_manifest_digest(image_ref, cmd="docker"):
    """ Return the repo and manifest digest of a given image reference.
    e.g quay.io/namespace/repo:tag -> (quay.io/namespace/repo, sha256:123456)
    """
    if len(image_ref.split("@")) == 2:
        # Still pull for a digest ref, to make sure the image exists
        repo, digest = image_ref.split("@")
        pull_command = [cmd, "pull", repo+"@"+tag]
        inspect_command = [cmd, "inspect", repo+"@"+tag]
    else:
        repo, tag = image_ref.split(":")
        pull_command = [cmd, "pull", repo+":"+tag]
        inspect_command = [cmd, "inspect", repo+":"+tag]

    try:
        subprocess.run(pull_command, check=True)
        out = subprocess.run(inspect_command, check=True, capture_output=True)
        parsed = json.loads(out.stdout)
        repo_digests = parsed[0]["RepoDigests"]
    except subprocess.CalledProcessError as cpe:
        logger.error("Error running docker commands for image %s:%s - %s", repo, tag, cpe)
        return None, None
    except ValueError as ve:
        logger.error("Error parsing docker inspect output output - %s", ve)
        return None, None
    except Exception as e:
        logger.error("Error getting the manifest digest for image %s:%s - %s", repo, tag, e)
        return None, None
    
    repo_digests = list(filter(lambda repo_digest: repo_digest.startswith(repo),repo_digests))
    if len(repo_digests) == 0:
        logger.error("Could not find the manifest digest for the given image %s:%s", repo, tag)
        return None, None

    manifest_digest = repo_digests[0].split("@")[-1]
    if not MANIFEST_DIGEST_REGEX.match(manifest_digest):
        logger.error("Unknown manifest digest format for %s:%s -> %s", repo_digest, manifest_digest)
        return None, None

    return repo, manifest_digest


def get_b64_logo_from_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
        
    return base64.b64encode(data).decode("ascii")


def parse_args():
    def version_arg_type(arg_value, pat=re.compile(VERSION_REGEX)):
        if not pat.match(arg_value):
            if MASTER_VERSION_REGEX.match(arg_value):
                return arg_value

            if not pat.match("v"+arg_value):
                raise argparse.ArgumentTypeError

            return "v"+arg_value
        return arg_value

    desc = 'Generate CSVs for tagged versions.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('version', help='Version to generate (SemVer). e.g v1.2.3', type=version_arg_type)
    parser.add_argument('previous_version', help='Previous version.', type=version_arg_type, nargs='?')
    parser.add_argument('--json', dest='yaml', help='Output json config (default).', action='store_false')
    parser.add_argument('--yaml', dest='yaml', help='Output yaml config.', action='store_true')
    parser.add_argument('--upstream', dest='downstream', help='Generate with upstream config.', action='store_false')
    parser.add_argument('--downstream', dest='downstream', help='Generate with downstream config.', action='store_true')
    parser.add_argument('--image', dest='image', help='Image to use in CSV.')
    parser.add_argument('--workdir', dest='workdir', help='Work directory', default=".")
    parser.add_argument('--output-dir', dest='output_dir', help='Output directory relative to the workdir', default="deploy")
    parser.add_argument('--skip-pull', dest='skip_pull', help='Skip pulling the image for verification', action='store_true')
    parser.set_defaults(yaml=True)
    parser.set_defaults(downstream=False)
    parser.set_defaults(previous_version=None)
    parser.set_defaults(skip_pull=False)

    logger.debug('Parsing all args')
    _, unknown = parser.parse_known_args()

    added_args_keys = set()
    while (len(unknown) > 0 and ARGUMENT_REGEX.match(unknown[0]) and
           ARGUMENT_REGEX.match(unknown[0]).end() == len(unknown[0])):
        logger.info('Adding argument: %s', unknown[0])
        added_args_keys.add(unknown[0].lstrip('-'))
        parser.add_argument(unknown[0])
        _, unknown = parser.parse_known_args()

    logger.debug('Parsing final set of args')
    return parser.parse_args(), added_args_keys


def main():
    all_args, added_args_keys = parse_args()
    template_kwargs = {key: getattr(all_args, key, None) for key in added_args_keys}

    ENV = Environment(loader=FileSystemLoader(os.path.join(all_args.workdir, TEMPLATE_DIR)), undefined=StrictUndefined)
    ENV.filters['normalize_version'] = normalize_version
    ENV.globals['get_current_datetime'] = get_current_datetime

    logo = (get_b64_logo_from_file(os.path.join(all_args.workdir, LOGO_DOWNSTREAM_FILE))
            if all_args.downstream else get_b64_logo_from_file(os.path.join(all_args.workdir,LOGO_UPSTREAM_FILE))
    )
    image_ref = all_args.image or CSO_IMAGE + ":" + CSO_IMAGE_TAG

    if not all_args.skip_pull:
        repo, image_manifest_digest = get_image_manifest_digest(image_ref)
        if not repo or not image_manifest_digest:
            sys.exit(1)

        container_image = repo + "@" + image_manifest_digest
    else:
        container_image = image_ref

    template_kwargs["version"] = all_args.version
    template_kwargs["previous_version"] = all_args.previous_version
    template_kwargs["logo"] = logo
    template_kwargs["container_image"] = container_image
    template_kwargs["k8s_api_version"] = template_kwargs.setdefault("k8s_api_version", K8S_API_VERSION)

    manifest_output_dir = os.path.join(all_args.output_dir, OUTPUT_MANIFEST_DIR, normalize_version(all_args.version))
    os.makedirs(manifest_output_dir,  exist_ok=True)
    generated_files = {}

    assert CSV_TEMPLATE_FILE.endswith(".clusterserviceversion.yaml.jnj")
    csv_template = ENV.get_template(CSV_TEMPLATE_FILE)
    generated_csv = csv_template.render(**template_kwargs)
    csv_filename = CSV_TEMPLATE_FILE.split(".")
    csv_filename.insert(1, all_args.version)
    csv_filename = ".".join(csv_filename[:-1])
    generated_files[os.path.join(manifest_output_dir, csv_filename)] = generated_csv

    for crd_template_file in filter(lambda filename: filename.endswith(".crd.yaml.jnj"), CRD_TEMPLATE_FILES):
        crd_template = ENV.get_template(crd_template_file)
        generated_crd = crd_template.render(**template_kwargs)
        generated_files[os.path.join(manifest_output_dir, crd_template_file.rstrip(".jnj"))] = generated_crd

    if all_args.yaml:
        for filepath, content in generated_files.items():
            with open(filepath, 'w') as f:
                f.write(content)
    else:
        for filepath, content in generated_files.items():
            parsed = yaml.load(content, Loader=yaml.SafeLoader)
            with open(filepath.rstrip("yaml")+"json", 'w') as f:
                f.write(json.dumps(parsed, default=str))


if __name__ == "__main__":
    main()
