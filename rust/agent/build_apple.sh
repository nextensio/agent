#!/usr/bin/env bash

if [ "$#" -ne 1 ] ; then
    echo "$0: Error missing argument [ios|macosx]"
    exit 1
fi

if [ "$1" = "ios" ]; then
  echo "build_apple.sh building target ios"
  cargo build --target aarch64-apple-ios --release
  cargo build --target x86_64-apple-ios --release
elif [ "$1" = "macosx" ]; then
  echo "build_apple.sh building target macosx"
  cargo build --target x86_64-apple-darwin --release
else
  echo "build_apple.sh missing target exiting"
  exit 2
fi
