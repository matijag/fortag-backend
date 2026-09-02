#!/usr/bin/env sh
set -eu

mode="${1:-unit}"

case "$mode" in
  unit)
    docker build --target builder -t fortag-backend-unit -f scanner/Dockerfile scanner
    docker run --rm --entrypoint go fortag-backend-unit test -v ./...
    ;;
  all)
    docker build -t fortag-backend-test-runner -f tests/integration/Dockerfile.test-runner .
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      --network host \
      fortag-backend-test-runner
    ;;
  *)
    echo "Usage: $0 [unit|all]" >&2
    exit 2
    ;;
esac
