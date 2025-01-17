#!/usr/bin/env bash

if [ "$#" -ne 2 ] ; then
    echo "$0: Error missing argument [ios|macosx]"
    exit 1
fi

echo "[Environment]"
env
echo ""
export CARGO_NET_GIT_FETCH_WITH_CLI=true

if [ "$1" = "ios" ]; then
  echo "build_apple.sh building target ios"
  cargo build --manifest-path=$2/agent/Cargo.toml --target aarch64-apple-ios --release
  cargo build --manifest-path=$2/agent/Cargo.toml --target x86_64-apple-ios --release
elif [ "$1" = "macosx" ]; then
  echo "build_apple.sh building target macosx"
  cargo build --manifest-path=$2/agent/Cargo.toml --target aarch64-apple-darwin --release
  cargo build --manifest-path=$2/agent/Cargo.toml --target x86_64-apple-darwin --release
else
  echo "build_apple.sh missing target exiting"
  exit 2
fi
