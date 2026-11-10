#!/usr/bin/env bash
# kata-run setup for bipnipd: build.rs compiles proto/admin.proto, so protoc must exist.
set -euo pipefail
if ! command -v protoc >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq protobuf-compiler >/dev/null
fi
protoc --version
