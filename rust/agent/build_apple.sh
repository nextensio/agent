#!/usr/bin/env bash

# cargo lipo --release
cargo build --target aarch64-apple-ios --release
cargo build --target x86_64-apple-ios --release
cargo build --target x86_64-apple-darwin --release