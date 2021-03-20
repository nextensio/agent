#!/usr/bin/env bash

# cargo lipo --release
cargo build --target aarch64-apple-ios --release
cargo build --target x86_64-apple-ios --release
cargo build --target x86_64-apple-darwin --release
\rm -rf ../target/libnextensioIOS.a
\rm -rf ../target/libnextensioMACOSX.a
lipo -create ../target/aarch64-apple-ios/release/libnextensio.a ../target/x86_64-apple-ios/release/libnextensio.a -output ../target/libnextensioIOS.a
lipo -create ../target/x86_64-apple-darwin/release/libnextensio.a -output ../target/libnextensioMACOSX.a
lipo -info ../target/libnextensioIOS.a
lipo -info ../target/libnextensioMACOSX.a
