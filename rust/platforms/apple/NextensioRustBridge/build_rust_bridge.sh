#!/bin/bash
source $HOME/.cargo/env
source ../../../../agent/build_apple.sh

RUST_TARGET=../../../../target
IOS_LIB=libnextensioIOS.a
MACOSX_LIB=libnextensioMACOSX.a
NXT_LIB=libnextensio.a

rm -f $RUST_TARGET/$IOS_LIB
rm -f $RUST_TARGET/$MACOSX_LIB
lipo -create $RUST_TARGET/aarch64-apple-ios/release/$NXT_LIB $RUST_TARGET/x86_64-apple-ios/release/$NXT_LIB -output $RUST_TARGET/$IOS_LIB
lipo -create $RUST_TARGET/x86_64-apple-darwin/release/$NXT_LIB -output $RUST_TARGET/$MACOSX_LIB

echo "[Rust Libraries]"
lipo -info $RUST_TARGET/$IOS_LIB
lipo -info $RUST_TARGET/$MACOSX_LIB
