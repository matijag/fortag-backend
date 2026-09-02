#!/usr/bin/env bash
set -euo pipefail

channel="${1:-}"
version="${2:-}"
image="${IMAGE:-}"

if [[ -z "$image" || -z "$channel" || -z "$version" ]]; then
  echo "Usage: IMAGE=registry.example/owner/fortag-backend $0 <beta|stable> <version>" >&2
  exit 2
fi

tags=(--tag "$image:$version")

case "$channel" in
  beta)
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || {
      echo "Beta versions must look like 1.1.0-rc.2" >&2
      exit 2
    }
    tags+=(--tag "$image:beta")
    ;;
  stable)
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo "Stable versions must look like 1.1.0" >&2
      exit 2
    }
    tags+=(--tag "$image:${version%.*}" --tag "$image:latest")
    ;;
  *)
    echo "Unknown channel '$channel'; expected beta or stable" >&2
    exit 2
    ;;
esac

builder="fortag-backend-builder"
if docker buildx inspect "$builder" >/dev/null 2>&1; then
  docker buildx use "$builder"
else
  docker buildx create --use --name "$builder"
fi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  "${tags[@]}" \
  --build-arg "BUILD_VERSION=$version" \
  --push \
  -f scanner/Dockerfile \
  scanner
