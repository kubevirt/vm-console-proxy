#!/bin/bash
set -e

# This file runs the tests.
# It is run from the root of the repository.

# These evn variables are defined by the CI:
# CI_IMG - path of the image in the local repository accessible on the CI

./automation/e2e-functests/deploy-kubevirt.sh

# Split image path into name and tag
IMG_SPLIT=(${CI_IMG//:/ })

export IMG_REPOSITORY=${IMG_SPLIT[0]}
export IMG_TAG=${IMG_SPLIT[1]}

make deploy functest
