#!/usr/bin/env bash
set -euo pipefail

# The user that clones the repository (root) is different from the user performing git commands
git config --global --add safe.directory /go/src/github.com/DataDog/lemur

if [[ "${gbilite_environment}" == "prod" ]]; then
  # For production runs, always re-build images for the latest release
  LATEST_RELEASE_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
  echo "lemur:${LATEST_RELEASE_TAG}"
  echo "lemur:latest"
else
  # For staging runs, always re-build the image for the latest commit
  LATEST_COMMIT=$(git rev-parse HEAD)
  echo "lemur:${LATEST_COMMIT}"
fi
