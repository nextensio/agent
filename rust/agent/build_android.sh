#!/usr/bin/env bash

# Android targets

cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target i686-linux-android --release
cargo build --target x86_64-linux-android --release

