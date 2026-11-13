#!/usr/bin/env bash
# Build the v5.8.9-oauth image with buildah (no docker/buildx needed).
#   scripts/build-oauth-image.sh <image-ref> [dashboard-zip]
# * builds from a clean clone of the committed HEAD (no _build, no untracked files)
# * with a dashboard zip given, pre-places priv/www so get-dashboard.sh skips the download
#   (its version file must say github_ref: refs/tags/$EMQX_DASHBOARD_VERSION)
# Same build args as ./build's docker target. --format docker: the Dockerfile relies on ONBUILD, which OCI format drops.
set -euo pipefail
IMAGE=${1:?image ref, e.g. registry.coder.baonq.me/coder/emqx:5.8.9-oauth.1}
ZIP=${2:-}
SRC=$(cd "$(dirname "$0")/.." && pwd)
. "$SRC/env.sh"
CTX=$(mktemp -d /var/tmp/emqx-oauth-ctx.XXXXXX)
trap 'rm -rf "$CTX"' EXIT
git clone -q --no-hardlinks --depth 1 "file://$SRC" "$CTX/emqx"
if [ -n "$ZIP" ]; then
  mkdir -p "$CTX/emqx/apps/emqx_dashboard/priv"
  (cd "$CTX/emqx/apps/emqx_dashboard/priv" && unzip -q "$ZIP" && mv dist www)
  grep -q "github_ref: refs/tags/$(grep -oP '^export EMQX_DASHBOARD_VERSION \?= \K.*' "$SRC/Makefile")" \
    "$CTX/emqx/apps/emqx_dashboard/priv/www/version" || { echo "dashboard zip version mismatch" >&2; exit 1; }
fi
buildah bud --layers --network host --format docker \
  -f "$CTX/emqx/deploy/docker/Dockerfile" \
  --build-arg BUILD_FROM="$EMQX_DOCKER_BUILD_FROM" \
  --build-arg RUN_FROM="$EMQX_DOCKER_RUN_FROM" \
  --build-arg SOURCE_TYPE=src \
  --build-arg PROFILE=emqx \
  --build-arg IS_ELIXIR=no \
  --build-arg SUFFIX= \
  --build-arg EXTRA_DEPS= \
  --label org.opencontainers.image.source=https://github.com/baonq-me/emqx \
  --label org.opencontainers.image.revision="$(git -C "$SRC" rev-parse HEAD)" \
  -t "$IMAGE" "$CTX/emqx"
