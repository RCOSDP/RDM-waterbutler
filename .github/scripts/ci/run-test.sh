#!/bin/bash
set -euo pipefail
set -x

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <TEST_BUILD>" >&2
    exit 1
fi

TEST_BUILD="$1"
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

read -r -d '' container_script <<'BASH' || true
export WHEELHOUSE=$HOME/wheelhouse
export WATERBUTLER_CONFIG=./travis-config.json
export BOTO_CONFIG-/dev/null
invoke test
BASH

docker run --rm -t \
    -e TEST_BUILD="$TEST_BUILD" \
    ${WB_TEST_IMAGE} bash -lc "$container_script"
