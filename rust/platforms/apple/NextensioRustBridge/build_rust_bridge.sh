#!/bin/bash
source $HOME/.cargo/env

echo "[PROJECT_DIR] "$PROJECT_DIR

#if [ "$#" -ne 1 ] ; then
#    echo "$0: Error missing argument [ios|macosx] expected"
#    exit 1
#fi

RUST_TARGET=$PROJECT_DIR/../../target
IOS_LIB=libnextensioIOS.a
MACOSX_LIB=libnextensioMacOSX.a
NXT_LIB=libnextensio.a
DEST_TARGET=$PROJECT_DIR/NextensioRustBridge

echo "[DEST_TARGET] "$DEST_TARGET

# build all apple targets
if [ "$1" = "ios" ]; then
  echo "[BUILDING TARGET] IOS"
  source $PROJECT_DIR/../../agent/build_apple.sh ios
  rm -f $DEST_TARGET/$IOS_LIB
  lipo -create $RUST_TARGET/aarch64-apple-ios/release/$NXT_LIB $RUST_TARGET/x86_64-apple-ios/release/$NXT_LIB -output $DEST_TARGET/$IOS_LIB
  lipo -info $DEST_TARGET/$IOS_LIB
elif [ "$1" = "macosx" ]; then
  echo "[BUILDING TARGET] MacOSX"
  source $PROJECT_DIR/../../agent/build_apple.sh macosx
  rm -f $DEST_TARGET/$MACOSX_LIB
  lipo -create $RUST_TARGET/x86_64-apple-darwin/release/$NXT_LIB -output $DEST_TARGET/$MACOSX_LIB
  lipo -info $DEST_TARGET/$MACOSX_LIB
else
  echo "[MISSING TARGET] exiting... "
  exit 2
fi

exit 0
